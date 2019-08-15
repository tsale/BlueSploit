import csv



def modules():
    mods = {'gather':'Gather Information','query':'Query Windows events','network':'Show current network information'}
    for k,v in mods.items():
        print("{}\t=>\t\t{}".format(k,v))




def write_csv():
    nlist = []
    ninput = input("Add your note:\n")
    #ninput = ("{}\n".format(ninput))
    nlist.append(ninput)
    with open('notes.csv', 'a',newline='') as csvFile:
        for x in nlist:
            writer = csv.writer(csvFile)
            writer.writerow([x])
            csvFile.close()


def show_notes():
    with open('notes.csv', 'r') as csvFile:
        reader = csv.reader(csvFile)
        for row in reader:
            print(row)
