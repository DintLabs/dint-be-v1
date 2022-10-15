
## Clone Project
1. Clone the Project on Local Machine.
2. Paste .env in Main Directory.


## Setting up Virtual Environment
1. python3.8 -m dint-venv (just outside project Directory)
2. Activate the Virtual Environment.
3. cd into the project directory.
4. run this command -> pip3.8 install -r requirements.txt
5. Start Docker for Redis Server(Django Channels) -> sudo docker run -p 6379:6379 -d redis:5


## Installation
1. run cp .env.sample .env
2. Create a database in Postgres and add relevent DB credentials in .env
3. Run python manage.py migrate.
4. Run python manage.py runserver.

Project is setup and ready to be used. 
Import postman collection by following link in postman
Link: https://www.getpostman.com/collections/d219db6087b032cb9ec6
