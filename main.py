"""
Password manager for keeping you passwords secure
"""
import tkinter as tk
import tkinter.messagebox
from tkinter import ttk
import sys


import cryptography.fernet
from sqlalchemy import create_engine, delete
from sqlalchemy.orm import Session
from models import Credentials, Portal
from install import install
from crypto import Crypto


class CheckPassword:
    """
    Check password
    """
    def __init__(self):
        """
        Initial CheckPassword class
        """
        self.pin = None
        pass_label = ttk.Label(check_password_tab, text="Be sure you wont forget your password!!!")
        pass_label.configure(font=("arial", 12))
        self.pass_entry = ttk.Entry(check_password_tab, show="*")
        pass_button = ttk.Button(check_password_tab, text="Submit")
        pass_button.bind("<Button-1>", self._pass_on_click)
        small_label = ttk.Label(check_password_tab, text="Please enter your password:")
        small_label.configure(font=("arial", 7))
        pass_label.pack(padx=5, pady=5)
        small_label.pack()
        self.pass_entry.pack(padx=5, pady=5)
        pass_button.pack(padx=5, pady=5)
        self.pass_entry.focus_set()
        self.pass_entry.bind("<Return>", self._pass_on_click)

    def _pass_on_click(self, event):
        """
        Check password on click
        :param event: default event parameter needed
        :return: None
        """
        if self.pass_entry.get():
            tab_system.tab(1, state="normal")
            tab_system.tab(2, state="normal")
            tab_system.tab(0, state="hidden")
            tab_system.select(1)
            self.pin = self.pass_entry.get()
            self.pass_entry.delete(0, 100)


class AddPassword:
    """
    Add password
    """
    def __init__(
        self,
        database,
        _index,
        tab_sys,
    ):
        """
        Initial AddPassword class
        :param database: sqlalchemy database connection
        :param _index: class inex
        :param tab_sys: tkinter tab system
        """
        self.crypto = None
        self.tab_sys = tab_sys
        self.index = _index
        self.database = database

        portal_label = ttk.Label(add_credentials_tab, text="Portal: ")
        self.portal_entry = ttk.Entry(add_credentials_tab)
        portal_label.grid(row=0, column=0, padx=5)
        self.portal_entry.grid(row=0, column=1, pady=5)

        login_label = ttk.Label(add_credentials_tab, text="Login: ")
        self.login_entry = ttk.Entry(add_credentials_tab)
        login_label.grid(row=1, column=0, padx=5)
        self.login_entry.grid(row=1, column=1, pady=5)

        password_label = ttk.Label(add_credentials_tab, text="Password: ")
        self.password_entry = ttk.Entry(add_credentials_tab, show="*")
        password_label.grid(row=2, column=0, padx=5)
        self.password_entry.grid(row=2, column=1, pady=5)

        button = ttk.Button(add_credentials_tab, text="Submit")
        style.configure(
            "TButton",
            background="#B5CDA3",
            foreground="white",
            width=10,
            borderwidth=5,
            focusthickness=5,
        )
        style.map("TButton", background=[("active", "#B3E283")])
        button.grid(row=3, column=0, columnspan=2, padx=5, pady=5)
        button.bind("<Button-1>", lambda x: self.on_click("", check.pin))

    def on_click(self, event, user_password):
        """
        Add credentials on click
        :param event: default event parameter needed
        :param user_password: user password for authentication
        :return: None
        """
        if all(
            [
                len(self.portal_entry.get()),
                len(self.login_entry.get()),
                len(self.password_entry.get()),
            ]
        ):
            self.crypto = Crypto(user_password)
            with Session(self.database) as session:
                portal = Portal(name=self.portal_entry.get())
                credentials = Credentials(
                    login=self.login_entry.get(),
                    password=self.crypto.encrypt(self.password_entry.get()),
                    portal=portal,
                )
                session.add_all([credentials, portal])
                session.commit()
                self.index.tree.insert(
                    "", "end", values=(credentials.portal.name, credentials.login)
                )
            self.tab_sys.select(1)
            tkinter.messagebox.showinfo(
                title="Add credentials", message="New credential added successfully"
            )
        self.portal_entry.delete(0, 100)
        self.login_entry.delete(0, 100)
        self.password_entry.delete(0, 100)


class IndexView:
    """
    Index view
    """
    def __init__(self, database):
        """
        Intializes IndexView class
        :param database: sqlalchemy database connection
        """
        self.crypto = None
        self.database = database
        self.tree = ttk.Treeview(
            index_tab,
            columns=("login", "password"),
            show="headings",
            height=10,
            selectmode="browse",
        )
        # style = ttk.Style(index_tab)
        style.configure(
            "Treeview.Heading",
            font=("Comic Sans MS", 10),
            background="#4C4C6D",
            foreground="yellow",
        )

        style.configure(
            "Treeview",
            font=("Comic Sans MS", 10),
            background="#DEEDF0",
            foreground="black",
            fieldbackground="#E8F6EF",
        )

        self.fill_treeview()
        self.configure_treeview()
        self.tree.bind("<<TreeviewSelect>>")
        self.tree.bind("<Double-1>", lambda x: self.on_click("", check.pin))
        self.tree.bind("<Delete>", self.delete_column)

    def configure_treeview(self):
        """
        Configures treeview method
        :return: None
        """
        self.tree.column("#1", anchor=tk.CENTER, stretch=tk.NO, width=200)
        self.tree.heading("#1", text="Portal")
        self.tree.column("#2", anchor=tk.CENTER, stretch=tk.NO, width=200)
        self.tree.heading("#2", text="Login")
        self.tree.pack(expand=1, fill="both")

    def fill_treeview(self):
        """
        Fills treeview method
        :return: None
        """
        with Session(self.database) as session:
            for credential in session.query(Credentials).all():
                self.tree.insert("", "end", values=(credential.portal.name, credential.login))

    def delete_column(self, event):
        """
        Deletes column from treeview
        :param event: tkinter event
        :return: None
        """
        message = tkinter.messagebox.askquestion(title='Delete record', message='Are you sure?')
        if message == "yes":
            selected_column = self.tree.focus()
            selected_items = self.tree.item(selected_column, "values")
            with Session(self.database) as session:
                session.execute(delete(Portal).where(Portal.name == selected_items[0]))
                session.execute(delete(Credentials).where(Credentials.login == selected_items[1]))
                session.commit()
            for item in self.tree.get_children():
                self.tree.delete(item)
            self.fill_treeview()

    def on_click(self, event, user_password):
        """
        On click method
        :param event: default tkinter event parameter
        :param user_password: user password for authentication
        :return: None
        """
        self.crypto = Crypto(user_password)
        selected_column = self.tree.focus()
        selected_items = self.tree.item(selected_column, "values")
        with Session(self.database) as session:
            credential = (
                session.query(Credentials)
                .join(Portal)
                .filter(Portal.name == selected_items[0], Credentials.login == selected_items[1])
                .one()
            )
            try:
                decrypted = self.crypto.decrypt(credential.password)
                root.clipboard_clear()
                root.clipboard_append(decrypted)
                tkinter.messagebox.showinfo(
                    title="Password", message="Password copied to clipboard"
                )
            except cryptography.fernet.InvalidToken:
                tkinter.messagebox.showwarning(title="Token", message="Token is invalid")
                tab_system.tab(1, state="hidden")
                tab_system.tab(2, state="hidden")
                tab_system.tab(0, state="normal")
                tab_system.select(0)


if __name__ == "__main__":
    engine = create_engine("sqlite:///database.db", future=True)
    if len(sys.argv) > 1 and sys.argv[1] == "install":
        install(engine)
        print("Tables has been created successfully")
        sys.exit()

    root = tk.Tk()
    root.title("Password manager   v1.1")
    root.attributes("-alpha", 0.9)
    root.attributes("-topmost", 1)
    root.iconbitmap("password-manager-ico.ico")

    tab_system = ttk.Notebook(root)
    style = ttk.Style(root)
    style.theme_use("clam")
    style.configure(
        "TNotebook.Tab", background="white", foreground="black", font=("Comic Sans MS", 10)
    )

    check_password_tab = ttk.Frame(tab_system)
    index_tab = ttk.Frame(tab_system)
    add_credentials_tab = ttk.Frame(tab_system)
    tab_system.pack(expand=1, fill="both")
    style_frame = ttk.Style()
    style_frame.configure(
        "TNotebook.Tab",
        foreground="#293462",
        font=(
            "Comic Sans MS",
            10,
        ),
    )

    check = CheckPassword()
    tab_system.add(check_password_tab, text="Check password", state="normal")
    tab_system.add(index_tab, text="View Credentials", state="hidden")
    tab_system.add(add_credentials_tab, text="Add password", state="hidden")

    index = IndexView(engine)
    AddPassword(engine, index, tab_system)

    root.mainloop()
