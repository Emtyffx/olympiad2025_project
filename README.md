# BDUT project

App for creativity house

Used technologies:

| Technology        | Purpose               |
|-------------------|-----------------------|
| Flask             | Web framework         |
| Flask-SQLAlchemy  | Database management   |
| SQLite            | Database              |
| Nix               | Dev shells            |
| Docker            | Containerization      |

# Launching in dev mode


```sh
# install needed dependencies
pip3 install -r requirements.txt

# launch the app
python3 -m app.py
```


# Launching in production environment(Docker)

Docker container is based on alpine 3.21 and contains python 3.12 (approx 70 MB)


```sh
# build container
docker build . --tag <specify-the-build-tag-here>

# launching container
docker run -it . -p 5000:5000 <specify-the-build-tag-here>
```

# Launching in production environment(non-Docker)

```sh
# install needed dependencies
pip3 install -r requirements.txt

# run the flask app
python3 -m flask run --host=0.0.0.0:5000
```


# Launching nix shell
```
nix shell
```



