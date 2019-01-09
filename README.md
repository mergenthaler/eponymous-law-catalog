# Eponymous Laws Catalog Project
Web app based in Python that serves as an Epynomous law catalog by category based on the Udacity Full Stack Web Developer II Nanodegree project

## About
This app provides a list of laws within a variety of categories. Registered users can post, edit, and delete their own items.

## Steps to run this project

1. Download and install [Vagrant](https://www.vagrantup.com/downloads.html).
2. Clone or download the Vagrant VM configuration for the [FSND](https://github.com/udacity/fullstack-nanodegree-vm).
3. `cd vagrant/`
4. 
   ```bash
   vagrant up
   ```
5. 
   ```bash
   vagrant ssh
   ```
6. Fork this repository and clone it
7. Set up the database:
    ```bash
    python db_setup.py
    ```
8. Populate the DB
    ```bash
    python populator.py
    ```
9. Run the app on
    ```bash
    python app.py
    ```
10. Open the app on `http://localhost:5000/`


## Thanks
This code was inspried by the Work of SDey96 on https://github.com/SDey96/Udacity-Item-Catalog-Project

