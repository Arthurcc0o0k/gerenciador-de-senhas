import os
import json
import sqlite3
import base64
import traceback
import random
import string
import threading
import pyperclip
from datetime import datetime
from tkinter import Tk, Label, Entry, Button, StringVar, Frame, Listbox, Scrollbar, END, messagebox, Toplevel, Text
from tkinter import filedialog
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

CONFIG_FILE = "config.json"
DB_FILE = "passwords.db"
KEY_FILE = "key.key"  # opcional, se você quiser armazenar a chave de forma persistente
CLIPBOARD_TIMEOUT = 30  # segundos para limpar clipboard


def generate_random_password(length: int = 16, use_special: bool = True) -> str:
    """Gera uma senha aleatória forte"""
    chars = string.ascii_letters + string.digits
    if use_special:
        chars += "!@#$%^&*()-_=+"
    return ''.join(random.choice(chars) for _ in range(length))


def copy_to_clipboard(text: str, timeout: int = CLIPBOARD_TIMEOUT):
    """Copia texto para clipboard e limpa após timeout"""
    try:
        pyperclip.copy(text)
        
        def clear_clipboard():
            import time
            time.sleep(timeout)
            pyperclip.copy("")
        
        thread = threading.Thread(target=clear_clipboard, daemon=True)
        thread.start()
        
        messagebox.showinfo("Sucesso", f"Senha copiada! Será limpa em {timeout}s")
    except Exception as e:
        messagebox.showerror("Erro", f"Erro ao copiar: {e}")


def export_passwords(fernet: Fernet, filename: str):
    """Exporta senhas para arquivo JSON (descriptografado)"""
    try:
        rows = get_passwords()
        export_data = []
        
        for item_id, company, username, service, enc_password, notes, created_at in rows:
            try:
                password = decrypt_secret(fernet, enc_password)
            except:
                password = "<erro ao descriptografar>"
            
            export_data.append({
                "company": company,
                "username": username,
                "service": service,
                "password": password,
                "notes": notes,
                "created_at": created_at
            })
        
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(export_data, f, indent=2, ensure_ascii=False)
        
        messagebox.showinfo("Sucesso", f"Dados exportados para {filename}")
    except Exception as e:
        messagebox.showerror("Erro", f"Erro ao exportar: {e}")


def import_passwords(fernet: Fernet, filename: str):
    """Importa senhas de arquivo JSON"""
    try:
        with open(filename, "r", encoding="utf-8") as f:
            import_data = json.load(f)
        
        count = 0
        for item in import_data:
            try:
                insert_password(
                    fernet,
                    item.get("company", ""),
                    item.get("username", ""),
                    item.get("service", ""),
                    item.get("password", ""),
                    item.get("notes", "")
                )
                count += 1
            except Exception as e:
                print(f"Erro ao importar: {e}")
        
        messagebox.showinfo("Sucesso", f"{count} entradas importadas com sucesso")
    except Exception as e:
        messagebox.showerror("Erro", f"Erro ao importar: {e}")


def change_master_password(old_password: str, new_password: str):
    """Altera a senha mestra"""
    try:
        # Verifica senha antiga
        verify_master_password(old_password)
        
        # Gera novo hash
        salt = os.urandom(16)
        new_master_hash = base64.urlsafe_b64encode(
            generate_master_key(new_password, salt)
        ).decode("utf-8")
        
        # Atualiza config
        config = load_config()
        config["salt"] = base64.urlsafe_b64encode(salt).decode("utf-8")
        config["master_hash"] = new_master_hash
        config["updated_at"] = datetime.utcnow().isoformat() + "Z"
        
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2)
        
        # Atualiza arquivo de chave
        with open(KEY_FILE, "wb") as f:
            f.write(base64.urlsafe_b64decode(new_master_hash.encode("utf-8")))
        
        messagebox.showinfo("Sucesso", "Senha mestra alterada com sucesso")
        return True
    except ValueError:
        messagebox.showerror("Erro", "Senha mestra atual incorreta")
        return False
    except Exception as e:
        messagebox.showerror("Erro", f"Erro ao alterar: {e}")
        return False


def generate_master_key(master_password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
        backend=default_backend(),
    )
    return base64.urlsafe_b64encode(kdf.derive(master_password.encode()))


def initialize_storage(master_password: str):
    if os.path.exists(CONFIG_FILE):
        raise RuntimeError("Configuração já existe")

    salt = os.urandom(16)
    master_hash = base64.urlsafe_b64encode(
        generate_master_key(master_password, salt)
    ).decode("utf-8")

    config = {
        "salt": base64.urlsafe_b64encode(salt).decode("utf-8"),
        "master_hash": master_hash,
        "created_at": datetime.utcnow().isoformat() + "Z"
    }

    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2)

    # emprestado para recuperação de chave: não recomendado em produção
    with open(KEY_FILE, "wb") as f:
        f.write(base64.urlsafe_b64decode(master_hash.encode("utf-8")))

    conn = sqlite3.connect(DB_FILE)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS passwords (id INTEGER PRIMARY KEY, company TEXT, username TEXT, service TEXT, password TEXT, notes TEXT, created_at TEXT)"
    )
    conn.commit()
    conn.close()


def load_config():
    if not os.path.exists(CONFIG_FILE):
        return None
    with open(CONFIG_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def verify_master_password(master_password: str) -> bytes:
    config = load_config()
    if not config:
        raise RuntimeError("Configuração não encontrada. Inicie o aplicativo e crie uma senha mestre.")

    salt = base64.urlsafe_b64decode(config["salt"].encode("utf-8"))
    candidate_key = generate_master_key(master_password, salt)
    stored_hash = base64.urlsafe_b64decode(config["master_hash"].encode("utf-8"))

    if candidate_key != stored_hash:
        raise ValueError("Senha mestra inválida")

    return candidate_key


def encrypt_secret(fernet: Fernet, plaintext: str) -> str:
    token = fernet.encrypt(plaintext.encode("utf-8"))
    return token.decode("utf-8")


def decrypt_secret(fernet: Fernet, token: str) -> str:
    return fernet.decrypt(token.encode("utf-8")).decode("utf-8")


def insert_password(fernet: Fernet, company: str, username: str, service: str, password: str, notes: str):
    conn = sqlite3.connect(DB_FILE)
    encrypted_password = encrypt_secret(fernet, password)

    conn.execute(
        "INSERT INTO passwords (company, username, service, password, notes, created_at) VALUES (?, ?, ?, ?, ?, ?)",
        (company, username, service, encrypted_password, notes, datetime.utcnow().isoformat())
    )
    conn.commit()
    conn.close()


def get_passwords():
    conn = sqlite3.connect(DB_FILE)
    items = conn.execute("SELECT id, company, username, service, password, notes, created_at FROM passwords ORDER BY created_at DESC").fetchall()
    conn.close()
    return items


def update_password(fernet: Fernet, item_id: int, company: str, username: str, service: str, password: str, notes: str):
    conn = sqlite3.connect(DB_FILE)
    encrypted_password = encrypt_secret(fernet, password)
    conn.execute(
        "UPDATE passwords SET company=?, username=?, service=?, password=?, notes=? WHERE id=?",
        (company, username, service, encrypted_password, notes, item_id)
    )
    conn.commit()
    conn.close()


def delete_password(item_id: int):
    conn = sqlite3.connect(DB_FILE)
    conn.execute("DELETE FROM passwords WHERE id=?", (item_id,))
    conn.commit()
    conn.close()


class PasswordManagerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Gerenciador de Senhas - Empresa")
        self.active_key = None
        self.fernet = None

        if not os.path.exists(CONFIG_FILE):
            self.show_setup_screen()
        else:
            self.show_login_screen()

    def show_setup_screen(self):
        self.clear_screen()

        Label(self.root, text="Bem-vindo ao Gerenciador de Senhas").pack(pady=10)
        Label(self.root, text="Crie uma senha mestra (lembre-se sempre)").pack()

        self.master_pwd_setup = StringVar()
        self.master_pwd_confirm = StringVar()

        Entry(self.root, textvariable=self.master_pwd_setup, show="*").pack(pady=5)
        Entry(self.root, textvariable=self.master_pwd_confirm, show="*").pack(pady=5)

        Button(self.root, text="Criar senha mestra", command=self.create_master_password).pack(pady=10)

    def show_login_screen(self):
        self.clear_screen()

        Label(self.root, text="Login no Gerenciador de Senhas").pack(pady=10)
        Label(self.root, text="Senha mestra").pack()

        self.master_pwd = StringVar()
        Entry(self.root, textvariable=self.master_pwd, show="*").pack(pady=5)

        Button(self.root, text="Entrar", command=self.login).pack(pady=8)

    def create_master_password(self):
        pwd = self.master_pwd_setup.get().strip()
        pwd_confirm = self.master_pwd_confirm.get().strip()
        if not pwd or not pwd_confirm:
            messagebox.showwarning("Aviso", "Preencha os dois campos")
            return
        if pwd != pwd_confirm:
            messagebox.showerror("Erro", "As senhas não coincidem")
            return

        try:
            initialize_storage(pwd)
            messagebox.showinfo("Sucesso", "Senha mestra criada com sucesso")
            self.show_login_screen()
        except Exception as e:
            traceback.print_exc()
            messagebox.showerror("Erro", f"Falha ao criar configuração: {e}")

    def login(self):
        pwd = self.master_pwd.get().strip()
        if not pwd:
            messagebox.showwarning("Aviso", "Digite a senha mestra")
            return

        try:
            key = verify_master_password(pwd)
            self.active_key = key
            self.fernet = Fernet(key)
            self.show_dashboard()
        except ValueError:
            messagebox.showerror("Erro", "Senha mestra incorreta")
        except Exception as e:
            traceback.print_exc()
            messagebox.showerror("Erro", str(e))

    def show_dashboard(self):
        self.clear_screen()
        Label(self.root, text="Painel de Controle - Empresa", font=("Arial", 14, "bold")).pack(pady=10)

        # Frame de busca
        search_frame = Frame(self.root)
        search_frame.pack(pady=5, padx=10, fill="x")
        
        Label(search_frame, text="Buscar:", font=("Arial", 10)).pack(side="left", padx=5)
        self.search_var = StringVar()
        self.search_var.trace("w", self.filter_list)
        Entry(search_frame, textvariable=self.search_var, width=40, font=("Arial", 10)).pack(side="left", padx=5)
        Button(search_frame, text="Limpar busca", command=lambda: self.search_var.set("")).pack(side="left", padx=5)

        # Frame para listbox
        frame = Frame(self.root)
        frame.pack(padx=10, pady=4, fill="both", expand=True)

        self.listbox = Listbox(frame, width=100, height=12, font=("Arial", 9))
        scrollbar = Scrollbar(frame, orient="vertical", command=self.listbox.yview)
        self.listbox.config(yscrollcommand=scrollbar.set)

        self.listbox.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # Frame de botões (linha 1)
        buttons1 = Frame(self.root)
        buttons1.pack(pady=5)

        Button(buttons1, text="➕ Adicionar", command=self.add_entry_dialog, bg="#4CAF50", fg="white").grid(row=0, column=0, padx=5)
        Button(buttons1, text="✏️  Editar", command=self.edit_entry_dialog, bg="#2196F3", fg="white").grid(row=0, column=1, padx=5)
        Button(buttons1, text="❌ Remover", command=self.remove_selected, bg="#f44336", fg="white").grid(row=0, column=2, padx=5)
        Button(buttons1, text="👁️  Ver senha", command=self.view_password, bg="#FF9800", fg="white").grid(row=0, column=3, padx=5)
        Button(buttons1, text="📋 Copiar", command=self.copy_password, bg="#9C27B0", fg="white").grid(row=0, column=4, padx=5)
        Button(buttons1, text="🔄 Atualizar", command=self.refresh_list, bg="#00BCD4", fg="white").grid(row=0, column=5, padx=5)

        # Frame de botões (linha 2)
        buttons2 = Frame(self.root)
        buttons2.pack(pady=5)

        Button(buttons2, text="🔐 Gerar senha", command=self.generate_password_dialog, bg="#3f51b5", fg="white").grid(row=0, column=0, padx=5)
        Button(buttons2, text="💾 Exportar", command=self.export_dialog, bg="#607D8B", fg="white").grid(row=0, column=1, padx=5)
        Button(buttons2, text="📂 Importar", command=self.import_dialog, bg="#455A64", fg="white").grid(row=0, column=2, padx=5)
        Button(buttons2, text="🔑 Mudar senha mestra", command=self.change_password_dialog, bg="#E91E63", fg="white").grid(row=0, column=3, padx=5)
        Button(buttons2, text="🚪 Sair", command=self.logout, bg="#795548", fg="white").grid(row=0, column=4, padx=5)

        self.all_passwords = get_passwords()
        self.refresh_list()

    def clear_screen(self):
        for widget in self.root.winfo_children():
            widget.destroy()

    def refresh_list(self):
        self.all_passwords = get_passwords()
        self.filter_list(None, None, None)

    def filter_list(self, *args):
        """Filtra a lista baseado na busca"""
        search_term = self.search_var.get().lower()
        self.listbox.delete(0, END)
        
        for r in self.all_passwords:
            item_id, company, username, service, _, notes, created_at = r
            entry_text = f"{item_id}: Empresa={company} | Usuário={username} | Serviço={service} | Nota={notes} | Criado={created_at}"
            
            # Filtra se o termo está em qualquer campo
            if search_term == "" or search_term in entry_text.lower():
                self.listbox.insert(END, entry_text)

    def add_entry_dialog(self):
        self.entry_window(mode="add")

    def edit_entry_dialog(self):
        selection = self.listbox.curselection()
        if not selection:
            messagebox.showwarning("Aviso", "Selecione um item para editar")
            return
        item = self.listbox.get(selection[0])
        item_id = int(item.split(":")[0])
        self.entry_window(mode="edit", item_id=item_id)

    def entry_window(self, mode: str, item_id=None):
        w = Toplevel(self.root)
        w.title("Cadastrar/Editar senha")

        Label(w, text="Empresa").grid(row=0, column=0, sticky="e")
        company_var = StringVar()
        Entry(w, textvariable=company_var, width=45).grid(row=0, column=1, padx=10, pady=4)

        Label(w, text="Usuário").grid(row=1, column=0, sticky="e")
        username_var = StringVar()
        Entry(w, textvariable=username_var, width=45).grid(row=1, column=1, padx=10, pady=4)

        Label(w, text="Serviço").grid(row=2, column=0, sticky="e")
        service_var = StringVar()
        Entry(w, textvariable=service_var, width=45).grid(row=2, column=1, padx=10, pady=4)

        Label(w, text="Senha").grid(row=3, column=0, sticky="e")
        password_var = StringVar()
        Entry(w, textvariable=password_var, width=45).grid(row=3, column=1, padx=10, pady=4)

        Label(w, text="Notas").grid(row=4, column=0, sticky="e")
        notes_var = StringVar()
        Entry(w, textvariable=notes_var, width=45).grid(row=4, column=1, padx=10, pady=4)

        if mode == "edit" and item_id is not None:
            row = [r for r in get_passwords() if r[0] == item_id]
            if row:
                _, company, username, service, enc_password, notes, _ = row[0]
                company_var.set(company)
                username_var.set(username)
                service_var.set(service)
                try:
                    password_var.set(decrypt_secret(self.fernet, enc_password))
                except Exception:
                    password_var.set("<erro ao descriptografar>")
                notes_var.set(notes)

        def save_action():
            company = company_var.get().strip()
            username = username_var.get().strip()
            service = service_var.get().strip()
            pwd = password_var.get().strip()
            notes = notes_var.get().strip()

            if not (company and username and service and pwd):
                messagebox.showwarning("Aviso", "Preencha os campos obrigatórios")
                return

            if mode == "add":
                insert_password(self.fernet, company, username, service, pwd, notes)
            else:
                update_password(self.fernet, item_id, company, username, service, pwd, notes)

            self.refresh_list()
            w.destroy()

        Button(w, text="Salvar", command=save_action).grid(row=5, column=0, columnspan=2, pady=10)

    def remove_selected(self):
        selection = self.listbox.curselection()
        if not selection:
            messagebox.showwarning("Aviso", "Selecione um item para remover")
            return

        item = self.listbox.get(selection[0])
        item_id = int(item.split(":")[0])
        if messagebox.askyesno("Confirmar", "Remover essa entrada?"):
            delete_password(item_id)
            self.refresh_list()

    def view_password(self):
        selection = self.listbox.curselection()
        if not selection:
            messagebox.showwarning("Aviso", "Selecione um item para ver a senha")
            return

        item = self.listbox.get(selection[0])
        item_id = int(item.split(":")[0])
        row = [r for r in self.all_passwords if r[0] == item_id]
        if not row:
            messagebox.showerror("Erro", "Entrada não encontrada")
            return

        _, company, username, service, enc_password, notes, created_at = row[0]
        try:
            decrypted = decrypt_secret(self.fernet, enc_password)
        except Exception as e:
            decrypted = "(não foi possível descriptografar)"

        messagebox.showinfo(
            "Senha de usuário",
            f"Empresa: {company}\nUsuário: {username}\nServiço: {service}\nSenha: {decrypted}\nNotas: {notes}\nCriado: {created_at}"
        )

    def copy_password(self):
        """Copia a senha selecionada para clipboard"""
        selection = self.listbox.curselection()
        if not selection:
            messagebox.showwarning("Aviso", "Selecione um item para copiar")
            return

        item = self.listbox.get(selection[0])
        item_id = int(item.split(":")[0])
        row = [r for r in self.all_passwords if r[0] == item_id]
        if not row:
            messagebox.showerror("Erro", "Entrada não encontrada")
            return

        _, company, username, service, enc_password, notes, created_at = row[0]
        try:
            decrypted = decrypt_secret(self.fernet, enc_password)
            copy_to_clipboard(decrypted)
        except Exception as e:
            messagebox.showerror("Erro", f"Erro ao copiar: {e}")

    def generate_password_dialog(self):
        """Abre diálogo para gerar senha"""
        w = Toplevel(self.root)
        w.title("Gerar Senha Aleatória")
        w.geometry("400x250")

        Label(w, text="Comprimento da senha", font=("Arial", 10)).pack(pady=5)
        length_var = StringVar(value="16")
        Entry(w, textvariable=length_var, width=10, font=("Arial", 11)).pack()

        Label(w, text="Incluir caracteres especiais?", font=("Arial", 10)).pack(pady=5)
        special_var = StringVar(value="sim")
        
        from tkinter import Radiobutton
        Radiobutton(w, text="Sim", variable=special_var, value="sim").pack()
        Radiobutton(w, text="Não", variable=special_var, value="nao").pack()

        def gerar_e_copiar():
            try:
                length = int(length_var.get())
                if length < 4 or length > 128:
                    messagebox.showwarning("Aviso", "Comprimento deve ser entre 4 e 128")
                    return
                
                use_special = special_var.get() == "sim"
                password = generate_random_password(length, use_special)
                
                result_label.config(text=f"Senha: {password}", font=("Arial", 9), fg="blue")
                copy_to_clipboard(password)
            except ValueError:
                messagebox.showerror("Erro", "Comprimento inválido")

        result_label = Label(w, text="", font=("Arial", 10), wraplength=380)
        result_label.pack(pady=10)

        Button(w, text="Gerar e Copiar", command=gerar_e_copiar, bg="#4CAF50", fg="white").pack(pady=10)

    def export_dialog(self):
        """Abre diálogo para exportar dados"""
        filename = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            initialfile=f"senhas_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        )
        if filename:
            export_passwords(self.fernet, filename)

    def import_dialog(self):
        """Abre diálogo para importar dados"""
        filename = filedialog.askopenfilename(
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        if filename:
            if messagebox.askyesno("Confirmar", "Importar dados? As entradas duplicadas serão ignoradas."):
                import_passwords(self.fernet, filename)
                self.refresh_list()

    def change_password_dialog(self):
        """Abre diálogo para mudar senha mestra"""
        w = Toplevel(self.root)
        w.title("Mudar Senha Mestra")
        w.geometry("400x250")

        Label(w, text="Senha mestra atual", font=("Arial", 10)).pack(pady=5)
        old_pwd_var = StringVar()
        Entry(w, textvariable=old_pwd_var, show="*", font=("Arial", 11)).pack()

        Label(w, text="Nova senha mestra", font=("Arial", 10)).pack(pady=5)
        new_pwd_var = StringVar()
        Entry(w, textvariable=new_pwd_var, show="*", font=("Arial", 11)).pack()

        Label(w, text="Confirmar nova senha", font=("Arial", 10)).pack(pady=5)
        confirm_pwd_var = StringVar()
        Entry(w, textvariable=confirm_pwd_var, show="*", font=("Arial", 11)).pack()

        def fazer_mudanca():
            old_pwd = old_pwd_var.get()
            new_pwd = new_pwd_var.get()
            confirm_pwd = confirm_pwd_var.get()

            if not old_pwd or not new_pwd or not confirm_pwd:
                messagebox.showwarning("Aviso", "Preencha todos os campos")
                return

            if new_pwd != confirm_pwd:
                messagebox.showerror("Erro", "As novas senhas não coincidem")
                return

            if len(new_pwd) < 6:
                messagebox.showwarning("Aviso", "A nova senha deve ter no mínimo 6 caracteres")
                return

            if change_master_password(old_pwd, new_pwd):
                w.destroy()

        Button(w, text="Mudar Senha", command=fazer_mudanca, bg="#E91E63", fg="white").pack(pady=10)

    def logout(self):
        self.active_key = None
        self.fernet = None
        self.show_login_screen()


if __name__ == "__main__":
    root = Tk()
    root.geometry("900x520")
    app = PasswordManagerApp(root)
    root.mainloop()
