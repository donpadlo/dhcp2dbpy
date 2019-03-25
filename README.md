FreeBSD:

pkg install python3
python3 -m ensurepip
pip3 install mysql-connector

Ubuntu:

sudo apt-get install python3
sudo apt-get install pip3
sudo pip3 install mysql-connector

Создаем БД MySQL, заливаем в неё  pydhcp.sql

Запуск сервера:

./pydhcpdb.py -d -c config.xml

- d режим вывода в консоль DEBUG
- c <имя_файла> конфигурационный файл

Более полное описание проекта: https://грибовы.рф/?page_id=4411