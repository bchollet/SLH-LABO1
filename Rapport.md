# SLH - Labo 2

## Questions

### What is the purpose of a JWT access token? And what is the purpose of a JWT refresh token? Why do we have both?

Il permet de limiter les accès à des ressources protégées.
Un refresh token permet à un client de récupérer un nouveau token d'accès sans avoir besoin que cet utilisateur reffectue une opération de login.

Nous avons les deux car cela permet de sécuriser certaines routes ayant accès à des ressources protégées et d'améliorer l'UX globale en évitant à l'utilisateur
de prouver son identité tous les X temps.

### Where are the access token stored? Where are the refresh token stored ?

Access: Ils sont stocké côté client sous la forme d'un cookie

Refresh: Ils sont stocké côté client dans le local storage

### Is it a good idea to store them there? Is there a better solution?
On pourrait stocker le token d'accès dans la session du navigateur, cela assurerait sa destruction lorsque l'utilisateur quitte l'application (en fermant l'onglet ou son navigateur) tout en gardant la facilité d'accès 
que propose l'API du localstorage. Le refresh token pourrait être stocké dans un cookie en activant certaines configuration pour le protéger:
- httpOnly à true pour empêcher sa lecture par du Javascript
- secure = true pour ne permettre sa transmission que par HTTPS
- sameSite = strict pour empêcher les CSRF (cette action n'est possible que si front et back sont dans le même domaine).