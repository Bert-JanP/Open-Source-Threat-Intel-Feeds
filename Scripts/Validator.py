import csv

valid_categories = ['SSL', 'IP', 'DNS', 'URL', 'MD5', 'SHA1', 'SHA256', 'CVEID']

banner = "Validating CSV file... \nIf no error is shown the CSV is correct."

def validate_csv(csv_file):
    with open(csv_file, 'r') as file:
        reader = csv.DictReader(file, delimiter=';')
        for idx, row in enumerate(reader, start=1):  # Start at line 2 (assuming 1-indexed line numbers)
            vendor = row.get('Vendor')
            description = row.get('Description')
            category = row.get('Category')
            url = row.get('Url')

            if not vendor:
                print(f"Vendor field is empty in line {idx + 1}")
            if not description:
                print(f"Description field is empty in line {idx + 1}")
            if not category:
                print(f"Category field is empty in line {idx + 1}")
            if not url:
                print(f"Url field is empty in line {idx + 1}")
            elif category not in valid_categories:
                print(f"Invalid category '{category}' in line {idx + 1}")

print(banner)
# For linux use: csv_file = '../ThreatIntelFeeds.csv'
# For windows use: csv_file = '..\ThreatIntelFeeds.csv'
csv_file = '../ThreatIntelFeeds.csv'
validate_csv(csv_file)
