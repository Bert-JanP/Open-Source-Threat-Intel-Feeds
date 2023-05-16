import csv

def count_categories(csv_file):
    category_counts = {}

    with open(csv_file, 'r') as file:
        reader = csv.DictReader(file, delimiter=';')
        for row in reader:
            category = row.get('Category')
            if category in category_counts:
                category_counts[category] += 1
            else:
                category_counts[category] = 1

    return category_counts

# Usage
csv_file = '..\ThreatIntelFeeds.csv'
category_counts = count_categories(csv_file)

# Generate Markdown table
table = "| Category | Count |\n"
table += "| --- | --- |\n"
for category, count in category_counts.items():
    table += f"| {category} | {count} |\n"

# Save Markdown table to file
output_file = "StatisticsTable.md"
with open(output_file, 'w') as file:
    file.write(table)

print(f"Markdown table has been saved to {output_file}.")
