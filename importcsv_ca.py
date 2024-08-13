#folder_path = r'C:\Users\splpil\OneDrive - SAS\splpil\62- CA Italy - Card Fraud Model PoC\CA_framework_PoC\Raw Data\test'
import pandas as pd
import os

# Ścieżka do folderu z plikami CSV
folder_path = r'C:\Users\splpil\OneDrive - SAS\splpil\62- CA Italy - Card Fraud Model PoC\CA_framework_PoC\Raw Data'

# Lista plików CSV w folderze
csv_files = [file for file in os.listdir(folder_path) if file.endswith('.csv')]

# Zmienne do przechowywania sumy, liczby rekordów i liczby wczytanych plików
total_amount = 0
total_records = 0
files_loaded = 0

# Iteracja po wszystkich plikach CSV
for file in csv_files:
    file_path = os.path.join(folder_path, file)
    # Wczytanie danych z pliku CSV z kodowaniem latin-1
    df = pd.read_csv(file_path, sep=';', encoding='latin-1')
    # Dodanie sumy z kolumny 'AMOUNT_BASE' do ogólnej sumy
    total_amount += df['AMOUNT_BASE'].sum()
    # Dodanie liczby rekordów w pliku do ogólnej liczby rekordów
    total_records += len(df)
    # Zwiększenie licznika wczytanych plików
    files_loaded += 1

    # Wypisanie liczby rekordów w pliku
    print(f"Liczba rekordów w pliku {file}: {len(df)}")

# Wyświetlenie ogólnej sumy, liczby rekordów i liczby wczytanych plików
print("Ogólna suma w kolumnie 'AMOUNT_BASE':", total_amount)
print("Ogólna liczba rekordów:", total_records)
print("Liczba wczytanych plików:", files_loaded)