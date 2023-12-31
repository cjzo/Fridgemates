Fridgemates

This is a project that allows roommates to collaboratively manage a shared fridge remotely. Through a single account, users can record and see the history of their fridge. Further documentation details a lower-level overview of the project.


This project is broken into a main python file (app.py) that uses Flask and webpage html files found in the templates folder (all ending in .html). Other important files are found etiher in the direct folder that app.py is found in and also the static folder (which contains the css and favicon.ico). The rest of this documentation will go in-depth into the individual programs and html files.

First, each page is an extension (using Jinja) of the layout.html page. This page includes the navbar and other HTML that is repeated through each of the .html files. The back-end database is all located within "fridge.db" and the other related files are found in "helpers.py" and "requirements.txt." The file "helpers.py" includes helper functions that are used within the website not included within app.py and "requirements.txt" is a small text file that includes the packages used within the project. Finally, the folder "flask_session" includes sessions created for the website from Flask.

The functionality of each HTML is designed to be rather straightforward, however the user-flow may not be as such. First, the user is expected to register an account at the /register path. After the user registers, they will automatically be logged in but have the option to log in for later access through the logout button. After creating an account/logging in, the user is expected to first add the roommates of the dorm room in the /roommates path where each person's name can be added and removed according to their text name. Afterward, the user can add items to their refrigerator through the /insert path. Inside this path, the roommate adding an item is recorded and required. The user then has freedom with their management, having the option to view the current fridge state (at the / path which loads the index.html page), the fridge history of items (at the /history path), and additional info (at the /info) path. A majority of the edge-case testing and bugs should be covered, but just in case, the issue will likely lie within data-base interacting with the front-end. More specifically, issues in datatypes or existance of data. However, these issues are not expected to arise.

To remove an item from the fridge, the user should first navigate to the / path (or the main index through clicking the Fridgemates logo in the top left). Afterward, they can select which roommate is editing and click the remove button in the table. Other functionality is rather straightforward and will not be outlined in detail in this README file.

The SQLite3 database is found in the "fridge.db" file. This database contains the following tables: roommates, storage, transactions, and users. Roommates records the roommates for each user id, so roommates will share an account on this website. Storage and transactions perform similar tasks, but it makes the backend much more straightforward: storage keep track of the current itmes in the firdge while transactions is a log of all actions performed on the fridge. Finally, users is a database the contains information regarding logins and fridge space. Thus, each of these tables can be related by user_id, though this is not done as it is unneeded.






