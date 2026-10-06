import tkinter as tk
from tkinter import messagebox, ttk

from matplotlib import container
from database import Database
import tkinter.simpledialog
from network import NetworkCalculator


class LoginWindow:
    def __init__(self, root):
        self.root = root
        self.root.title("FINDMYIP - Connexion")
        self.root.geometry("400x600")
        self.root.configure(bg="#f4f7f9")
        self.root.resizable(False, False)

        # Titre
        tk.Label(self.root, text="Connexion", font=("Segoe UI", 20, "bold"), 
                 bg="#f4f7f9", fg="#2c3e50").pack(pady=20)

        try:
            self.image = tk.PhotoImage(file="icons.png").subsample(2, 2)
            tk.Label(self.root, image=self.image, bg="#f4f7f9").pack(pady=10)
        except:
            pass

        # Champs
        container = tk.Frame(self.root, bg="#f4f7f9")
        container.pack(pady=10, padx=40, fill="x")

        tk.Label(container, text="Nom d'utilisateur", bg="#f4f7f9", font=("Segoe UI", 10)).pack(anchor="w")
        self.username_entry = tk.Entry(container, font=("Segoe UI", 11))
        self.username_entry.pack(fill="x", pady=(5, 15))

        tk.Label(container, text="Mot de passe", bg="#f4f7f9", font=("Segoe UI", 10)).pack(anchor="w")
        self.password_entry = tk.Entry(container, show="*", font=("Segoe UI", 11))
        self.password_entry.pack(fill="x", pady=5)

        self.btn_show = tk.Button(container, text="Afficher le mot de passe", command=self.toggle_password,
                                  relief="flat", bg="#f4f7f9", fg="#3498db", font=("Segoe UI", 9))
        self.btn_show.pack(anchor="e")

        tk.Button(self.root, text="SE CONNECTER", command=self.valider_connexion,
                  bg="#2ecc71", fg="white", font=("Segoe UI", 12, "bold"), 
                  relief="flat", cursor="hand2", height=2).pack(pady=20, padx=40, fill="x")

    def toggle_password(self):
        if self.password_entry.cget("show") == "*":
            self.password_entry.config(show="")
            self.btn_show.config(text="Masquer le mot de passe")
        else:
            self.password_entry.config(show="*")
            self.btn_show.config(text="Afficher le mot de passe")

    def valider_connexion(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get()

        if Database.verifier_login(username, password):
            role = Database.verifier_login(username , password)
            self.lancer_dashboard(role)
        else:
            messagebox.showerror("Erreur", "Identifiants incorrects")

    def lancer_dashboard(self, role):
        for widget in self.root.winfo_children():
            widget.destroy()
        FindMyIPApp(self.root, role)

class FindMyIPApp:
    def __init__(self, root, role="user"):
        self.root = root
        self.root.title("FINDMYIP - Dashboard")
        self.root.geometry("800x600")
        self.root.configure(bg="#f4f7f9")
        self.role = role

        # Configuration du style
        self.style = ttk.Style()
        self.style.configure("TButton", font=("Segoe UI", 10), padding=10)
        
        self.setup_main_menu()

    def setup_main_menu(self):
        tk.Label(self.root, text="FINDMYIP", font=("Segoe UI", 24, "bold"), 
                 bg="#f4f7f9", fg="#2c3e50").pack(pady=30)
        
        # Grille pour les boutons
        container = tk.Frame(self.root, bg="#f4f7f9")
        container.pack(expand=True)

        buttons = [
            ("Générateur de Masques", self.ouvrir_generateur),
            ("Validateur Format IP", self.ouvrir_validateur),
            ("Analyseur de Propriétés", self.ouvrir_analyseur),
            ("Masque de Classe", self.ouvrir_masque_classe),
            ("Réseau & Sous-Réseau", self.ouvrir_subnetting),
            ("Vérificateur Connexion", self.ouvrir_comm),
            ("Infos Application", self.ouvrir_infos)
        ]
        
        if self.role == "admin":
            buttons.insert(6,("Ajouter un Utilisateur", self.ouvrir_ajout_user))

        for i, (text, func) in enumerate(buttons):
            row, col = divmod(i, 2)
            btn = tk.Button(container, text=text, command=func, width=28, height=2,
                           bg="#ffffff", fg="#34495e", font=("Segoe UI", 10),
                           relief="flat", cursor="hand2", bd=1)
            btn.grid(row=row, column=col, padx=15, pady=10)
            # Petit effet au survol
            btn.bind("<Enter>", lambda e, b=btn: b.config(bg="#ecf0f1"))
            btn.bind("<Leave>", lambda e, b=btn: b.config(bg="#ffffff"))

    # --- ACTIONS ---

    def ouvrir_generateur(self):
        win = tk.Toplevel(self.root)
        win.title("Tableau des Masques")
        win.geometry("900x600")
        
        donnees = NetworkCalculator.generer_donnees_masques()
        
        # Affichage dans un tableau (Treeview) pour que ce soit pro
        cols = ("prefixe", "decimal", "binaire")
        tree = ttk.Treeview(win, columns=cols, show="headings")
        tree.heading("prefixe", text="CIDR")
        tree.heading("decimal", text="Masque Décimal")
        tree.heading("binaire", text="Masque Binaire")
        
        for d in donnees:
            tree.insert("", "end", values=(d["prefixe"], d["decimal"], d["binaire"]))
        
        tree.pack(expand=True, fill="both", padx=10, pady=10)

    def ouvrir_validateur(self):
        win = tk.Toplevel(self.root)
        win.title("Validateur de Format IP")
        win.geometry("400x200")
        tk.Label(win, text="Entrez une adresse IP :").pack(pady=10)
        ent_ip = tk.Entry(win); ent_ip.pack()
        lbl_res = tk.Label(win, text="", pady=20)
        lbl_res.pack()
        def valider():
            ip = ent_ip.get()
            if NetworkCalculator.verifier_ip(ip):
                lbl_res.config(text=f"{ip} est une adresse IP valide.", fg="green")
            else:
                lbl_res.config(text=f"{ip} n'est pas une adresse IP valide.", fg="red")

        tk.Button(win, text="Valider", command=valider).pack(pady=10)

    def ouvrir_analyseur(self):
        win= tk.Toplevel(self.root)
        win.title("Analyseur de Propriétés")
        win.geometry("400x300")
        tk.Label(win, text="Entrez une adresse IP :").pack(pady=10)
        ent_ip = tk.Entry(win); ent_ip.pack()
        lbl_res = tk.Label(win, text="", pady=20)
        lbl_res.pack()
        def analyser():
            ip = ent_ip.get()
            if ip and NetworkCalculator.verifier_ip(ip):
                res = NetworkCalculator.analyser_ip(ip)
                msg = f"Classe : {res['classe']}\nType : {res['type']}\nÉtat : {res['status']}"
                lbl_res.config(text=msg, fg="blue")
            else:
                lbl_res.config(text=f"{ip} n'est pas une adresse IP valide.", fg="red")
        tk.Button(win, text="Analyser", command=analyser).pack(pady=10)
        
    def ouvrir_masque_classe(self):
        win= tk.Toplevel(self.root)
        win.title("Masque de Classe")
        win.geometry("400x200")
        tk.Label(win, text="Entrez une adresse IP :").pack(pady=10)
        ent_ip = tk.Entry(win); ent_ip.pack()
        lbl_res = tk.Label(win, text="", pady=20)
        lbl_res.pack()
        def obtenir():
            ip = ent_ip.get()
            if ip and NetworkCalculator.verifier_ip(ip):
                classe, masque = NetworkCalculator.obtenir_masque_classe(ip)
                lbl_res.config(text=f"Classe : {classe}\nMasque par défaut : {masque}", fg="blue")
            else:
                lbl_res.config(text=f"{ip} n'est pas une adresse IP valide.", fg="red")     
        tk.Button(win, text="Obtenir Masque", command=obtenir).pack(pady=10)

    def ouvrir_subnetting(self):
        win = tk.Toplevel(self.root)
        win.title("ID Réseau & Sous-Réseau")
        win.geometry("400x300")
        
        tk.Label(win, text="IP:").pack(pady=5)
        ent_ip = tk.Entry(win); ent_ip.pack()
        tk.Label(win, text="Masque:").pack(pady=5)
        ent_m = tk.Entry(win); ent_m.pack()
        
        lbl_res = tk.Label(win, text="", pady=20)
        lbl_res.pack()

        def calculer():
            res, err = NetworkCalculator.calculer_ids_reseau(ent_ip.get(), ent_m.get())
            if err: messagebox.showerror("Erreur", err)
            else:
                txt = f"Réseau Classful : {res['reseau_classful']}\nSous-Réseau : {res['sous_reseau']}"
                lbl_res.config(text=txt, fg="blue")

        tk.Button(win, text="Calculer", command=calculer).pack()

    def ouvrir_comm(self):
        win = tk.Toplevel(self.root)
        win.title("Test de Communication")
        win.geometry("450x400")
        
        tk.Label(win, text="Machine 1 IP / Masque").pack()
        e1_ip = tk.Entry(win); e1_ip.pack()
        e1_m = tk.Entry(win); e1_m.pack()
        
        tk.Label(win, text="\nMachine 2 IP / Masque").pack()
        e2_ip = tk.Entry(win); e2_ip.pack()
        e2_m = tk.Entry(win); e2_m.pack()
        
        lbl_res = tk.Label(win, text="", pady=20, font=("Arial", 10, "bold"))
        lbl_res.pack()

        def tester():
            res, err = NetworkCalculator.tester_communication(e1_ip.get(), e1_m.get(), e2_ip.get(), e2_m.get())
            if err: lbl_res.config(text=err, fg="red")
            else:
                m1_voit_m2, m2_voit_m1 = res
                status = "Communication Possible ✅" if (m1_voit_m2 and m2_voit_m1) else "Problème de Routage ⚠️"
                color = "green" if (m1_voit_m2 and m2_voit_m1) else "orange"
                lbl_res.config(text=f"M1 -> M2: {m1_voit_m2}\nM2 -> M1: {m2_voit_m1}\n\n{status}", fg=color)

        tk.Button(win, text="Vérifier", command=tester, bg="#2980b9", fg="white").pack(pady=10)

    def ouvrir_ajout_user(self):
        win = tk.Toplevel(self.root)
        win.title("Ajouter un Utilisateur")
        win.geometry("400x300")
        win.configure(bg="#f4f7f9")
        win.resizable(False, False)
        tk.Label(win, text="Ajouter un Utilisateur", font=("Segoe UI", 16, "bold"),
             bg="#f4f7f9", fg="#2c3e50").pack(pady=20)

        container = tk.Frame(win, bg="#f4f7f9")
        container.pack(pady=10, padx=40, fill="x")

        tk.Label(container, text="Nom d'utilisateur", bg="#f4f7f9", font=("Segoe UI", 10)).pack(anchor="w")
        ent_user = tk.Entry(container, font=("Segoe UI", 11))
        ent_user.pack(fill="x", pady=(5, 15))

        tk.Label(container, text="Mot de passe", bg="#f4f7f9", font=("Segoe UI", 10)).pack(anchor="w")
        ent_pwd = tk.Entry(container, show="*", font=("Segoe UI", 11))
        ent_pwd.pack(fill="x", pady=5)
        
        def enregistrer():
            user = ent_user.get().strip()
            pwd = ent_pwd.get()
            if user and pwd:
                if Database.enregister_user(user, pwd):
                    messagebox.showinfo("Succès", "Utilisateur enregistré !")
                    win.destroy()
                else:
                    messagebox.showerror("Erreur", "Échec de l'enregistrement.")
            else:
                messagebox.showwarning("Attention", "Remplis tous les champs.")

        tk.Button(win, text="AJOUTER", command=enregistrer,
              bg="#2ecc71", fg="white", font=("Segoe UI", 12, "bold"),
              relief="flat", cursor="hand2", height=2).pack(pady=20, padx=40, fill="x")
        

    def ouvrir_infos(self):
        fenetre_info = tk.Toplevel(self.root)
        fenetre_info.title("Spécifications Techniques")
        fenetre_info.geometry("700x700")
        
        texte_complet = (
            "les infos sur l'application\n"
            "" + "="*60 + "\n\n"
            "1. TABLEAU DES MASQUES :\n"
            "   Afficher tous les masques de /8 à /30 sous 3 formes :\n"
            "   -> Notation CIDR (ex: /24)\n"
            "   -> Binaire (ex: 11111111.11111111.11111111.00000000)\n"
            "   -> Décimal pointé (ex: 255.255.255.0)\n\n"
            "2. VALIDATION DE FORMAT :\n"
            "   Déterminer si une adresse IP entrée au clavier est valide\n\n"
            "3. ANALYSE DES PROPRIÉTÉS :\n"
            "   Déterminer la CLASSE (A, B, C, D, E) et préciser s'il s'agit d'une :\n"
            "   -> Adresse RÉSERVÉE (ex: 127.0.0.1)\n"
            "   -> Adresse PRIVÉE (ex: 192.168.x.x)\n\n"
            "4. MASQUE DE CLASSE :\n"
            "   Donner le masque par défaut (Classful) selon la classe de l'IP.\n\n"
            "5. RÉSEAU ET SOUS-RÉSEAU :\n"
            "   Calculer l'ID Réseau et l'ID Sous-réseau à partir de l'IP et du masque.\n\n"
            "6. VÉRIFICATION BILATÉRALE :\n"
            "   Déterminer si 2 IPs sont dans le même réseau :\n"
            "   -> Test A voit B : (IP_B appartient au réseau de A)\n"
            "   -> Test B voit A : (IP_A appartient au réseau de B)\n\n"
            "7. Ajouter un utilisateur :\n"
            "   -> Entrer les informations de l'utilisateur\n"
            "   -> Valider les informations\n"
        )

        label_cadre = tk.Label(fenetre_info, text=texte_complet, justify="left", 
                              font=("Courier New", 10), padx=20, pady=20, bg="white", relief="sunken")
        label_cadre.pack(expand=True, fill="both", padx=10, pady=10)
        tk.Button(fenetre_info, text="Compris", command=fenetre_info.destroy).pack(pady=10)

if __name__ == "__main__":
    root = tk.Tk()
    app = LoginWindow(root)
    root.mainloop()