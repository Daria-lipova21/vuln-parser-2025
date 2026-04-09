# Парсинг уязвимостей за 2025 год

Проект на Python, который автоматически собирает данные об уязвимостях с MITRE и MSRC, объединяет их и сохраняет в базу PostgreSQL.
Каждая уязвимость оценивается по собственным критериям, чтобы можно было составлять топ-листы для анализа и изучения.

## Функционал

– Сбор данных об уязвимостях за 2025 год с MITRE (MITRE CVE Program) и MSRC (Microsoft Security Response Center)

– Нормализация и объединение данных в единую структуру

– Ранжирование уязвимостей по уровню критичности

– Сохранение в PostgreSQL 

– Подготовка топ-списков для дальнейшего анализа

## Используемые форматы данных

– JSON (MITRE)

– XML (MSRC)

– ZIP-архив (для MITRE)

– SQL (PostgreSQL для хранения и индексации)

## Технологии и библиотеки

– Python 3.12

–`requests` - HTTP-запросы 

– `xml.etree.ElementTree` - парсинг XML 

– `datetime`, `re`, `io`, `os`, `zipfile`, `json` - стандартные библиотеки Python

– `psycopg2-binary` - подключение к PostgreSQL 

## Пример данных в базе

<img width="712" height="238" alt="db1" src="https://github.com/user-attachments/assets/def98b28-5854-4020-94ff-9d092fedd6e8" />

## Как запустить

– Установить зависимости: pip install -r requirements.txt

– Настроить .env файл с параметрами базы данных

– Запустить парсеры: python main.py
