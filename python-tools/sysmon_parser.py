events = []
current_event = {}
import csv

with open("sample_sysmon_export.txt", "r") as f:
    for line in f:
       cleaned = line.strip()

       if cleaned.startswith("TimeCreated"):
           if current_event:
               events.append(current_event)
           current_event = {}

       if ":" in cleaned:
           key, value = cleaned.split(":", 1)
           key = key.strip()
           value = value.strip()
           current_event[key] = value

if current_event:
    events.append(current_event)

for event in events:
    print(event)

with open("sysmon_output.csv", "w", newline="") as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow(["TimeCreated", "Image", "TargetObject"])

    for event in events:
        writer.writerow([
            event.get("TimeCreated", ""), 
            event.get("Image", ""), 
            event.get("TargetObject", "")

        ]) 

print("CSV file 'sysmon_output.csv' has been created successfully.")
        


    