import time
import glob
import fnmatch
from bs4 import BeautifulSoup
import matplotlib.pyplot as plt
import base64
from io import BytesIO
import datetime
from ResourceMonitor import ResourceMonitor

# Nazwa pliku, który zostanie wygenerowany (aby go wykluczyć z analizy)
REPORTS_DIR = "/var/www/reports/"

OUTPUT_FILENAME = f"combined_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
EX_FILENAME = "combined_report_*.html"

def get_html_files():
    """
    Znajduje wszystkie pliki .html w bieżącym katalogu,
    wykluczając plik wynikowy.
    """
    
    search_pattern = os.path.join(REPORTS_DIR, "*.html")

    # Znajdź wszystkie pliki kończące się na .html
    all_files = glob.glob(search_pattern)
    
    # Wyklucz plik wynikowy, jeśli już istnieje, aby nie analizować raportu końcowego
    files_to_process = []

    for f in all_files:
        filename = os.path.basename(f)

        if not fnmatch.fnmatch(filename, EX_FILENAME):
            files_to_process.append(f)
    
    files_to_process.sort() # Sortujemy, aby kolejność była przewidywalna
    return files_to_process

def parse_html_reports(file_list):
    """
    Analizuje listę plików HTML i sumuje statystyki błędów.
    """
    stats = {
        "404 Not Found": 0,
        "401/403 Forbidden": 0,
        "DoS Suspected IPs": 0,
        "Total Requests Analyzed": 0
    }
    
    reports_processed = []

    for file_name in file_list:
        try:
            with open(file_name, 'r', encoding='utf-8') as f:
                soup = BeautifulSoup(f, 'html.parser')
                
                # Pobieramy tytuł, aby rozpoznać typ raportu
                if soup.title and soup.title.string:
                    title = soup.title.string
                else:
                    # Jeśli brak tytułu, pomijamy ten plik (to może nie być raport)
                    continue

                # --- Parsowanie Raportów 404 ---
                if "404 Errors" in title:
                    summary_table = soup.find("h2", string="Summary")
                    if summary_table:
                        table = summary_table.find_next("table")
                        for row in table.find_all("tr"):
                            cols = row.find_all("td")
                            if len(cols) >= 2:
                                metric = cols[0].get_text().strip()
                                value = cols[1].get_text().strip()
                                if "Total 404 Errors" in metric:
                                    stats["404 Not Found"] += int(value)
                    reports_processed.append(file_name)

                # --- Parsowanie Raportów 401/403 ---
                elif "401/403 Errors" in title:
                    summary_table = soup.find("h2", string="Summary")
                    if summary_table:
                        table = summary_table.find_next("table")
                        for row in table.find_all("tr"):
                            cols = row.find_all("td")
                            if len(cols) >= 2:
                                metric = cols[0].get_text().strip()
                                value = cols[1].get_text().strip()
                                if "Total 401/403 Errors" in metric:
                                    stats["401/403 Forbidden"] += int(value)
                    reports_processed.append(file_name)

                # --- Parsowanie Raportu DoS ---
                elif "DoS Detection" in title:
                    summary_table = soup.find("h2", string="Summary")
                    if summary_table:
                        table = summary_table.find_next("table")
                        for row in table.find_all("tr"):
                            cols = row.find_all("td")
                            if len(cols) >= 2:
                                if "Total logs" in cols[0].get_text():
                                    stats["Total Requests Analyzed"] += int(cols[1].get_text())
                    
                    suspect_header = soup.find("h2", string=lambda text: text and "Suspected Offending IPs" in text)
                    if suspect_header:
                        suspect_table = suspect_header.find_next("table")
                        if suspect_table:
                            # Odejmujemy 1 za nagłówek tabeli
                            ip_count = len(suspect_table.find_all("tr")) - 1
                            stats["DoS Suspected IPs"] += max(0, ip_count)
                    reports_processed.append(file_name)
                    
        except Exception as e:
            print(f"Błąd podczas przetwarzania pliku {file_name}: {e}")

    return stats, reports_processed

def generate_charts(stats, resource_stats):
    """
    Generuje wykresy (kołowy i słupkowy) w base64.
    """
    charts_base64 = {}
    
    # Filtrujemy dane do wykresów (pomiń Total Requests, bo to inna skala)
    error_data = {k: v for k, v in stats.items() if k != "Total Requests Analyzed" and v > 0}
    
    if not error_data:
        return {}

    labels = list(error_data.keys())
    values = list(error_data.values())

    # --- 1. Wykres Kołowy ---
    plt.figure(figsize=(8, 6))
    plt.pie(values, labels=labels, autopct='%1.1f%%', startangle=140, colors=['#ff9999','#66b3ff','#99ff99'])
    plt.title('Procentowy udział typów incydentów')
    
    buffer = BytesIO()
    plt.savefig(buffer, format='png')
    buffer.seek(0)
    charts_base64['pie'] = base64.b64encode(buffer.getvalue()).decode('utf-8')
    plt.close()

    # --- 2. Wykres Słupkowy ---
    plt.figure(figsize=(8, 6))
    bars = plt.bar(labels, values, color=['#ff6666','#4d94ff','#4dff88'])
    plt.title('Liczba incydentów')
    plt.ylabel('Ilość')
    plt.grid(axis='y', linestyle='--', alpha=0.7)
    
    for bar in bars:
        yval = bar.get_height()
        plt.text(bar.get_x() + bar.get_width()/2, yval, int(yval), va='bottom', ha='center')

    buffer = BytesIO()
    plt.savefig(buffer, format='png')
    buffer.seek(0)
    charts_base64['bar'] = base64.b64encode(buffer.getvalue()).decode('utf-8')
    plt.close()

    if resource_stats:
        labels = ['CPU (%)', 'Pamięć (MB)', 'Odczyt dysku (KB/s)', 'Zapis dysku (KB/s)']
        values = [resource_stats['CPU'], resource_stats['Memory'], resource_stats['Disk Read'], resource_stats['Disk Write']]
        
        plt.figure(figsize=(8, 6))
        bars = plt.bar(labels, values, color=['#ffcc00', '#66ccff', '#99ff66', '#ff9966'])
        plt.title('Zużycie zasobów')
        plt.ylabel('Wartość')
        plt.grid(axis='y', linestyle='--', alpha=0.7)
        
        for bar in bars:
            yval = bar.get_height()
            plt.text(bar.get_x() + bar.get_width()/2, yval, round(yval, 2), va='bottom', ha='center')
        buffer = BytesIO()
        plt.savefig(buffer, format='png')
        buffer.seek(0)
        charts_base64['resource_bar'] = base64.b64encode(buffer.getvalue()).decode('utf-8')
        plt.close()

    return charts_base64

def create_html_report(stats,resource_stats, charts, processed_files):
    """
    Generuje kod HTML raportu.
    """
    html_content = f"""<!doctype html>
<html lang='pl'>
<head>
    <meta charset='utf-8'>
    <title>Zbiorczy Raport Błędów</title>
    <style>
        body{{font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 40px; background-color: #f4f4f9; color: #333;}}
        .container {{max-width: 900px; margin: 0 auto; background: #fff; padding: 30px; box-shadow: 0 0 15px rgba(0,0,0,0.1); border-radius: 8px;}}
        h1{{color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 15px;}}
        h2{{color: #34495e; margin-top: 30px;}}
        ul {{list-style-type: none; padding: 0;}}
        li {{background: #eef2f5; margin: 5px 0; padding: 8px; border-radius: 4px; border-left: 4px solid #3498db;}}
        table{{width:100%; border-collapse:collapse; margin-top: 15px;}}
        th, td{{padding: 12px; border-bottom: 1px solid #ddd; text-align: left;}}
        th{{background-color: #f8f9fa;}}
        .chart-section{{display: flex; flex-wrap: wrap; justify-content: space-around; gap: 20px; margin-top: 30px;}}
        .chart-box{{flex: 1 1 400px; text-align: center; border: 1px solid #eee; padding: 15px; border-radius: 8px;}}
        img {{max-width: 100%; height: auto;}}
    </style>
</head>
<body>
    <div class="container">
        <h1>Zbiorczy Raport Bezpieczeństwa</h1>
        <p>Data wygenerowania: {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
        
        <h2>Przetworzone pliki ({len(processed_files)})</h2>
        <ul>
            {''.join(f'<li>{os.path.basename(f)}</li>' for f in processed_files)}
        </ul>
        
        <h2>Statystyki</h2>
        <table>
            <tr><th>Metryka</th><th>Wartość</th></tr>
            <tr><td>Błędy 404 (Not Found)</td><td>{stats['404 Not Found']}</td></tr>
            <tr><td>Błędy 401/403 (Forbidden)</td><td>{stats['401/403 Forbidden']}</td></tr>
            <tr><td>Podejrzane adresy IP (DoS)</td><td>{stats['DoS Suspected IPs']}</td></tr>
            <tr style="background-color: #e8f4fd;"><td><strong>Przeanalizowane żądania (Total)</strong></td><td><strong>{stats['Total Requests Analyzed']}</strong></td></tr>
        </table>

        <h2>Zużycie zasobów</h2>
        <table>
            <tr><th>Metryka</th><th>Wartość</th></tr>
            <tr><td>CPU (%)</td><td>{resource_stats['CPU']:.2f}</td></tr>
            <tr><td>Pamięć (MB)</td><td>{resource_stats['Memory']:.2f}</td></tr>
            <tr><td>Odczyt dysku (KB/s)</td><td>{resource_stats['Disk Read']:.2f}</td></tr>
            <tr><td>Zapis dysku (KB/s)</td><td>{resource_stats['Disk Write']:.2f}</td></tr>
        </table>

        <h2>Wizualizacja</h2>
        <div class="chart-section">
            <div class="chart-box">
                <h3>Udział Błędów (Wykres Kołowy)</h3>
                {'<img src="data:image/png;base64,' + charts['pie'] + '">' if 'pie' in charts else '<p>Brak danych do wykresu</p>'}
            </div>
            <div class="chart-box">
                <h3>Liczba Błędów (Wykres Słupkowy)</h3>
                {'<img src="data:image/png;base64,' + charts['bar'] + '">' if 'bar' in charts else '<p>Brak danych do wykresu</p>'}
            </div>
        </div>
    </div>
</body>
</html>
"""
    return html_content

def main(name):
    # 1. Pobierz listę plików dynamicznie
    files = get_html_files()
    
    if not files:
        print("Nie znaleziono żadnych plików .html w bieżącym katalogu.")
        return

    print(f"Znaleziono {len(files)} plików HTML do analizy.")
    print("Rozpoczynam przetwarzanie...")
    
    # 2. Przeanalizuj pliki
    stats, processed = parse_html_reports(files)
    
    if not processed:
        print("Nie udało się pobrać danych z żadnego pliku (lub pliki nie są raportami).")
        return

    resource_monitor = ResourceMonitor()
    resource_monitor.get_user_resource_usage()
    time.sleep(1)
    cpu, memory, disk_read, disk_write = resource_monitor.get_user_resource_usage()
    resource_stats = {
        'CPU': cpu,
        'Memory': memory,
        'Disk Read': disk_read,
        'Disk Write': disk_write
    }
    
    # 3. Wygeneruj wykresy
    print("Generowanie wykresów...")
    charts = generate_charts(stats)
    
    # 4. Zbuduj HTML
    print("Tworzenie raportu HTML...")
    html_out = create_html_report(stats, charts, processed)
    
    with open(name, "w", encoding='utf-8') as f:
        f.write(html_out)
        
    print(f"Gotowe! Raport zapisano jako: {os.path.abspath(OUTPUT_FILENAME)}")

if __name__ == "__main__":
    main()