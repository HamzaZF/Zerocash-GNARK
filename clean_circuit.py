import os
import shutil

# Chemin du dossier à nettoyer
folder_path = "./_run"

# Vérifie si le dossier existe avant de tenter de supprimer son contenu
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
    print("Tous les fichiers du dossier './_run' ont été supprimés.")
else:
    print(f"Le dossier '{folder_path}' n'existe pas.")
