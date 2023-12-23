# API Autenticación

API para generar la autenticación token algoritmo SHA-256

###  Requisitos

Para construir esta aplicación se requieren como versiones mínimas:

* Java 17
* Maven 3.2.0

El puerto de despliegue es el default

```
8080
```

### Variables de entorno

* AUTH_CLIENT_ID: URI de conexión a Mongo DB (mongodb://localhost:27017)
* AUTH_CLIENT_PASSWORD: Nombe de la DB en mongo
* AUTH_REDIRECT_URI: Porcentaje de Valuación (Por defecto es 80)
* AUTH_USER_NAME: URI de conexión a Mongo DB (mongodb://localhost:27017)
* AUTH_USER_PASSWORD: Nombe de la DB en mongo
* AUTH_USER_ROL: Porcentaje de Valuación (Por defecto es 80)