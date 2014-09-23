# H1 Engine
======
1. Flask
2. python-rq
3. boto
4. fabric
5. zope.interface


# H2 Assumptions
1. Engine is hosted on http://engine.xdocker.org
2. Engine is running.


# H3 Registering the user

```php
curl -H "Accept: application/json" -H "Content-type: application/json" -X POST -d ' {"username": "xdocker", "password":"xdocker"}'  http://engine.xdocker.org/register
{
  "message": "Successfully registered", 
  "status": "OK"
}

```

# H3 Authenticate the user

```php
curl -H "Accept: application/json" -H "Conent-type: application/json" -X POST -d ' {"username": "xdocker", "password":"xdocker"}'  http://engine.xdocker.org/authenticate
{
  "status": "OK", 
  "token": "WyJYZXJ2bW9uIiwiODM1MGJiZjA0NDMxNzI2MDRkYTcwYzE1Yjc3ZWMwZWYiXQ.BwKC7w.PyM6S6CbykVvxiCN19y98_JuphU"
}
```
