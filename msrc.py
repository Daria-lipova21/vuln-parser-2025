import requests
import xml.etree.ElementTree as ET
from datetime import datetime
import re
from typing import List, Optional
from db import get_connection

# Константы
YEAR = 2025
SEVERITY_LIMIT = 4.0
MSRC_URL = 'https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/{month}'


class CVE:
    """Класс для хранения информации об одной уязвимости"""

    def __init__(
            self,
            cve_id: str,
            description: str,
            severity: float,
            published_date: Optional[str],
            affected_products: Optional[str]
    ):
        self.cve_id = cve_id
        self.description = description
        self.severity = severity
        self.published_date = published_date
        self.source = 'MSRC'
        self.affected_products = affected_products


class MSRCParser:
    """Основной класс для загрузки, парсинга и хранения уязвимостей msrc"""

    NAMESPACES = {
        'cvrf': 'http://www.icasi.org/CVRF/schema/cvrf/1.1',
        'vuln': 'http://www.icasi.org/CVRF/schema/vuln/1.1',
        'prod': 'http://www.icasi.org/CVRF/schema/prod/1.1'
    }

    def __init__(self, target_year: int, severity_limit: float):
        """Инициализация парсера с годом и порогом критичности"""
        self.year = target_year
        self.severity_limit = severity_limit
        self.vulnerabilities: List[CVE] = []
        self.no_severity = 0
        self.low_severity = 0

    def get_months(self) -> List[str]:
        """Возвращает список месяцев"""
        return [
            f'{self.year}-{datetime(self.year, m, 1).strftime('%b')}'
            for m in range(1, 13)
        ]

    def fetch_xml(self, month: str) -> str:
        """Загружает данные за указанный месяц"""
        url = MSRC_URL.format(month=month)
        response = requests.get(
            url,
            headers={'Accept': 'application/xml'},
            timeout=45
        )
        response.raise_for_status()
        return response.text

    @staticmethod
    def extract_date(text: str) -> Optional[str]:
        """Извлекает дату"""
        match = re.search(r'(\d{4}-\d{2}-\d{2})', text)
        return match.group(1) if match else None

    def parse_vulnerabilities(self, xml: str) -> List[CVE]:
        """Парсит XML и возвращает список cve строго за 2025 год"""
        root = ET.fromstring(xml)
        ns = self.NAMESPACES

        product_path = './/prod:FullProductName'
        vuln_path = './/vuln:Vulnerability'
        cve_path = 'vuln:CVE'
        score_path = './/vuln:CVSSScoreSets/vuln:ScoreSet'
        base_score_path = 'vuln:BaseScore'
        title_path = 'vuln:Title'
        note_path = './/vuln:Notes/vuln:Note'
        tracking_path = './/cvrf:DocumentTracking/cvrf:InitialReleaseDate'
        product_id_path = './/vuln:ProductID'

        # Собираем все продукты для быстрого поиска
        products_dict = {}
        for product in root.findall(product_path, ns):
            product_id = product.get('ProductID')
            product_name = product.text
            if product_id and product_name:
                products_dict[product_id] = product_name.strip()

        vulnerabilities_list: List[CVE] = []

        for vuln_element in root.findall(vuln_path, ns):
            cve_id = None
            for cve_element in vuln_element.findall(cve_path, ns):
                if cve_element.text and cve_element.text.startswith('CVE-'):
                    cve_id = cve_element.text.strip()
                    break
            if not cve_id:
                continue

            # Пропускаем cve не за 2025 год
            if not cve_id.startswith(f"CVE-{self.year}-"):
                continue

            # Получаем оценку критичности
            severity = None
            for score_set in vuln_element.findall(score_path, ns):
                for base_elem in score_set.findall(base_score_path, ns):
                    try:
                        severity = float(base_elem.text)
                        break
                    except (TypeError, ValueError):
                        continue
                if severity is not None:
                    break

            # Пропускаем, если критичность не указана или ниже порога
            if severity is None:
                self.no_severity += 1
                continue
            if severity < self.severity_limit:
                self.low_severity += 1
                continue

            # Формируем описание
            description = ''
            for title_element in vuln_element.findall(title_path, ns):
                if title_element.text:
                    description = title_element.text.strip()
                    break
            for note_element in vuln_element.findall(note_path, ns):
                if note_element.text and len(note_element.text) > 30:
                    description += ' ' + note_element.text.strip()
            description = re.sub(r'<[^>]+>', ' ', description)
            description = re.sub(r'\s+', ' ', description).strip()
            if not description:
                description = 'No description'
            description = description[:2500]

            # Пытаемся определить дату публикации
            published_date = None

            # Проверяем стандартные теги
            for tag_name in ['DateFirstPublished', 'InitialReleaseDate']:
                date_path = f'.//vuln:{tag_name}'
                for date_element in vuln_element.findall(date_path, ns):
                    if date_element.text:
                        try:
                            dt = datetime.fromisoformat(date_element.text.replace('Z', '+00:00'))
                            if dt.year == self.year:
                                published_date = dt.date().isoformat()
                                break
                        except ValueError:
                            continue
                if published_date:
                    break

            # Если не найдено - извлекаем из заметок только с нужным годом
            if not published_date:
                for note_element in vuln_element.findall(note_path, ns):
                    if note_element.text:
                        extracted_date = self.extract_date(note_element.text)
                        if extracted_date and extracted_date.startswith(str(self.year)):
                            published_date = extracted_date
                            break

            # Если всё ещё нет даты - используем дату документа
            if not published_date:
                for date_element in root.findall(tracking_path, ns):
                    if date_element.text:
                        try:
                            dt = datetime.fromisoformat(date_element.text.replace('Z', '+00:00'))
                            if dt.year == self.year:
                                published_date = dt.date().isoformat()
                                break
                        except ValueError:
                            continue

            if not published_date:
                continue

            # Формируем список затронутых ПО
            affected_products_list = []
            for product_id_element in vuln_element.findall(product_id_path, ns):
                product_id = product_id_element.text
                if product_id in products_dict:
                    affected_products_list.append(products_dict[product_id])
            if not affected_products_list:
                for product in root.findall(product_path, ns):
                    if product.text:
                        affected_products_list.append(product.text.strip())
            affected_products_str = (
                ', '.join(affected_products_list[:15]) if affected_products_list else None
            )

            # Создаём объект cve
            vulnerabilities_list.append(CVE(
                cve_id=cve_id,
                description=description,
                severity=severity,
                published_date=published_date,
                affected_products=affected_products_str
            ))

        return vulnerabilities_list

    def run(self):
        """Запускает основной процесс парсинга MSRC"""
        for month in self.get_months():
            xml = self.fetch_xml(month)
            self.vulnerabilities.extend(self.parse_vulnerabilities(xml))


class Database:
    """Класс для сохранения cve в БД"""
    def __init__(self, vulns: List[CVE]):
        self.vulns = vulns

    def save(self) -> int:
        if not self.vulns:
            return 0
        conn = get_connection()
        cur = conn.cursor()
        query = """
            INSERT INTO vulnerabilities
            (cve_id, description, severity, published_date, source, affected_products)
            VALUES (%s,%s,%s,%s,%s,%s)
            ON CONFLICT (cve_id) DO NOTHING
        """
        for vulnerability in self.vulns:
            cur.execute(
                query,
                (
                    vulnerability.cve_id,
                    vulnerability.description,
                    vulnerability.severity,
                    vulnerability.published_date,
                    vulnerability.source,
                    vulnerability.affected_products
                )
            )
        conn.commit()
        cur.close()
        conn.close()
        return len(self.vulns)
