

def space():
    print("\n")


def title(title):
    nb = int(30-len(title)/2)
    print(" "*nb,"#"*len(title)," "*nb)
    print("#"*nb, title, "#"*nb)    
    print(" "*nb,"#"*len(title)," "*nb)
    print("\n")

def subtitle(title):
    nb = int(30-len(title)/2)
    print("-"*len(title))
    print(title)    
    print("-"*len(title))
    print("\n")    