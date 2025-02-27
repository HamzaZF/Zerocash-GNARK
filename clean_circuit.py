import os
import shutil

# Chemin des dossiers à nettoyer
folder_paths = ["./_run_default", "./_run_register", "./_run_oneCoin", "./_run_F1", "./_run_2coin", "./_run_F2", "./_run_3coin", "./_run_F3", "./_run_draw"]

# Vérifie si le dossier existe avant de tenter de supprimer son contenu
for folder_path in folder_paths:
    if os.path.exists(folder_path):
        for filename in os.listdir(folder_path):
            file_path = os.path.join(folder_path, filename)
            try:
                if os.path.isfile(file_path) or os.path.islink(file_path):
                    os.remove(file_path)  # Supprime le fichier ou le lien symbolique
                elif os.path.isdir(file_path):
                    shutil.rmtree(file_path)  # Supprime le dossier et son contenu
            except Exception as e:
                print(f"Erreur lors de la suppression de {file_path}: {e}")
        # Message de confirmation après suppression de tous les fichiers/dossiers
        print(f"Tous les fichiers du dossier '{folder_path}' ont été supprimés.")
    else:
        print(f"Le dossier '{folder_path}' n'existe pas.")
