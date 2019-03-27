FreeBSD:
```shell
pkg install python3
python3 -m ensurepip
pip3 install mysql-connector
```
Ubuntu:
```shell
sudo apt install python3 python3-pip
sudo pip3 install -U pip # otherwise next'll fail because pip from apt package is outdated
sudo pip3 install mysql-connector
```
Создаем БД MySQL, заливаем в неё  pydhcp.sql

Запуск сервера:

`./pydhcpdb.py -d -c config.xml`

- d режим вывода в консоль DEBUG
- c <имя-файла> конфигурационный файл

Более полное описание проекта: https://грибовы.рф/?page_id=4411