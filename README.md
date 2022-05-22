# ICR - Laboratoire n°2
## Gestionnaire de mots de passe
<br>
<br>

Ce laboratoire a pour objectif d'implémenter un gestionnaire de mots de passe sécurisé avec les bonnes pratiques cryptographiques. <br>
Ce gestionnaire de mots de passe doit posséder les fonctionnalités suivantes : <br>
- Afficher/Récupérer un mot de passe enregistré
- Changement du mot de passe maître
- Partage d'un mot de passe avec un autre utilisateur <br>

En plus des fonctionnalités basiques :
- Création d'un compte
- Connexion à un compte

Le mot de passe maître est le seul et l'unique mot de passe que l'utilisateur doit connaître.<br>


Un compte est identifié par un nom d'utilisateur ainsi qu'un mot de passe de maître afin de s'y connecter. <br>
Le principal objectif est de sécuriser entièrement le mot de passe maître ainsi que les mots de passe enregistrés sur le gestionnaire.<br>
Un compte possède deux états : l'état verrouillé et l'état déverrouillé<br>
<br>
### Etat verrouillé : <br>
- Un attaquant ne doit pas être en mesure de retrouver les mots de passe, le mot de passe maître y compris.
- Un attaquant ne doit pas être en mesure de bruteforce le mot de passe maître non-trivial.
<br>
### Etat déverrouillé : <br>
- Un attaquant ne doit pas pouvoir retrouver le mot de passe maître dans la mémoire.
- Les mots de passe non demandé ne doivent pas être visible en clair.
<br>


# Sommaire : 

### A. Modèle de sécurité
> #### 1. Gestion du mot de passe maître 
>> #### Création du compte
>> #### Connexion au compte
> #### 2. Gestion des mots de passe
>> ##### Enregistrer un nouveau mot de passe
>> ##### Voir/Accéder aux mots de passe
>> ##### Partager un mot de passe avec un utilisateur
### B. Comment utiliser le password manager ?


<br>
<br>

# A. Modèle de sécurité

<br>

## 1. Gestion du mot de passe maître

<br>

Algorithmes utilisés :
- Argon2id (argon2-cffi 21.3.0)
- PRNG de la librairie Crypto.Random de Pycryptodome
- Chacha20-Poly1305, clé de 256 bits

La gestion du mot de passe maître est essentiel dans le gestionnaire de mots de passe, car en plus d'authentifier l'utilisateur sur son compte, il va nous permettre de générer les clés qui vont être utilisés pour chiffrer et déchiffrer les mots de passe que l'utilisateur va enregistré sur son gestionnaire.
<br><br>
#### Termes utilisé :
- Mot de passe maître : Mot de passe utilisé par l'utilisateur pour se connecter à son compte. 
- Empreinte du mot de passe maître : Hash du mot de passe maître stocké en base de données.
- Clé maître : Deuxième hash du mot de passe maître utilisé comme clé de chiffrement. Non stocké en base de données, stockage de son sel.
- Clé des mots de passes : Clé utilisé pour chiffrer les mots de passe de l'utilisateur.

<br>

### Création du compte

Lors de la création du compte, un nom d'utilisateur ainsi qu'un mot de passe maître va être demandé à l'utilisateur.
Celui-ci va le taper deux fois pour être sûr qu'il n'ait pas fait d'erreur.<br>

Ce mot de passe maître va être hashé grâce à l'algorithme Argon2id. Celui-ci génère un sel aléatoire pour chaque nouveau mot de passe ajouté. La version 2id maximise la résistance contre les attaques GPUs et les "side-channel attack".
L'empreinte sera alors stocké avec le nom d'utilisateur dans la base de données.<br>

Le mot de passe maître sera hashé une deuxième fois avec un sel différent pour générer la clé maître. Le sel sera stocké en base de données.
La clé maître est ensuite utilisé pour chiffrer une clé générée aléatoirement grâce au PRNG de PyCryptodome avec Chacha20-Poly1305, utilisé pour chiffrer les futures mots de passe de l'utilisateur. Cette clé chiffrée est également stocké en base de données.<br>

Une fois le processus terminé, la clé maître ne sera plus accessible.

Avantages de cette méthode :
- La fuite de l'empreinte du mot de passe maître (par dump de base de données) ne permet pas à un attaquant de déchiffrer les mots de passe de l'utilisateur.
- Le sel généré par Argon limite les bruteforces sur le mot de passe maître.
- Un changement du mot de passe maître n'impacte pas le chiffrement des anciens mots de passe. La clé utilisée pour les chiffrer ne changera pas, uniquement la clé maître sera modifié.

<br>

### Connexion au compte

A chaque fois que l'utilisateur se connecte, l'empreinte du mot de passe maître est vérifié. Si celle-ci est correcte alors l'utilisateur sera authentifié.<br>
Nous récupérons la clé maître en effectuant le hash depuis le mot de passe maître et le sel stocké en base de données.<br>
La clé de mots de passe est alors déchiffré et pourra être utilisé pour chiffrer ou déchiffrer les mots de passe de l'utilisateur.
Lorsque celui-ci se déconnecte, la clé maître et la clé des mots de passes sont oubliées.

<br>

### Changement du mot de passe maître

Si l'utilisateur veut changer son mot de passe maître, il devra d'abord rentrer son ancien mot de passe. Quelques changements seront alors effectué :
- L'empreinte du mot de passe maître sera modifié en base de données.
- La clé maître sera modifié, donc un sel sera regénéré puis modifié en base de données.
- La clé des mots de passe sera déchiffré par l'ancienne clé maître puis rechiffré par la nouvelle.


## 2. Gestion des mots de passe

Algorithmes utilisés:
- Chacha20-Poly1305, clé de 256 bits
- RSA-OAEP, clé de 2048 bits

Comme expliqué précédemment, la clé de chiffrement des mots de passe est généré aléatoirement à la création du compte de l'utilisateur. Celle-ci est chiffré par la clé maître généré depuis le mot de passe maître de l'utilisateur. L'algorithme qui a été choisi pour le chiffrement de cette clé et de tout les mots de passe de l'utilisateur est Chacha20-Poly1305. Il nous permet l'authentification des mots de passe en plus du chiffrement. De plus, cet algorithme de chiffrement par flots est très simple d'utilisation et permet d'intégrer des données (header) supplémentaires dans le MAC. On verra dans notre cas que cette fonctionnalité est très utile. La taille de clé choisi est de 256 bits pour les deux processus de chiffrement (clé des mots de passe + mots de passe).

### Enregistrer un nouveau mot de passe

Tout les mots de passe d'un utilisateur sont stocké dans un fichier qui lui est propre.
Lorsqu'un utilisateur souhaite ajouter un nouveau mot de passe, nous allons utiliser Chacha20-Poly1305. 
Afin de garantir l'intégrité des données enregistrées, nous ajoutons le nom du site internet comme `header`. 
Cela nous permet de l'authentifier avec le mot de passe qui correspond, sans que ce dernier soit chiffré (car cela n'est pas nécessaire). De cette manière, un attaquant qui souhaiterait altérer les données en inversant les mots de passe des sites sera remarqué.


### Voir/Accéder aux mots de passe

Quand l'utilisateur est connecté, aucun mots de passe n'est stocké en clair. Ces derniers sont déchiffrés lorsque l'utilisateur en fait la demande.
Il peut alors décider :
- d'afficher le mot de passe en clair
- de le copier dans le presse papier 


### Partager un mot de passe avec un utilisateur

La fonctionnalité partage de mot de passe est complexe à implémenter car elle nécessite de sécuriser l'échange entre deux utilisateurs. Afin de répondre à ce besoin, j'ai décidé d'utiliser l'algorithme de chiffrement asymétrique RSA-OAEP, appelé PKCS1_OAEP dans la librairie PyCryptodome. <br>

- Lors de la création d'un compte utilisateur, une paire de clé RSA est créée est stocké dans des fichiers à part. Avant d'être stocké, la clé privé est d'abord chiffrée avec Chacha20-Poly1305 en utilisant la clé des mots de passe (celle généré grâce au mot de passe maître)

- Quand un utilisateur veut partager un mot de passe, il récupère la clé publique du destinataire. Le mot de passe qu'il souhaite partager est d'abord déchiffré avec sa propre clé avant de la rechiffrer avec la clé publique de RSA. Le module utilisé pour chiffrer avec RSA s'appelle PKCS1_OAEP.

- Quand le destinataire veut voir le mot de passe partagé, il récupère sa clé privé qu'il déchiffre avec sa propre clé, puis il déchiffre le mot de passe.

- Chaque utilisateur possède 2 fichiers pour les mots de passe partagés : un pour les mots de passe envoyé à quelqu'un, et un pour ceux reçus.









