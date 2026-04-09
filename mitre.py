import json
import os
import io
import zipfile
from typing import List, Optional, Dict, Any, Tuple
import requests
from db import get_connection

# Константы
ZIP_URL = 'https://github.com/CVEProject/cvelistV5/archive/refs/heads/main.zip'
YEAR = '2025'
SAVE_FOLDER = 'mitre_2025'
CVSS_VERSIONS = ['cvssV3_1', 'cvssV3_0', 'cvssV2_0']
SEVERITY_LIMIT = 4.0


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
        self.source = 'MITRE'
        self.affected_products = affected_products


class MITREParser:
    """Основной класс для загрузки, парсинга и сохранения cve"""

    def __init__(self, zip_url: str, year: str, save_folder: str):
        self.zip_url = zip_url
        self.year = year
        self.save_folder = save_folder

    def download_and_extract(self):
        """Скачивает zip и распаковывает json за нужный год"""
        print('Загрузка архива cvelistV5-main.zip с github')
        response = requests.get(self.zip_url, stream=True)
        response.raise_for_status()

        with zipfile.ZipFile(io.BytesIO(response.content)) as zip_file:
            file_list = zip_file.namelist()

            files_to_extract = [
                file_path
                for file_path in file_list
                if file_path.startswith(f'cvelistV5-main/cves/{self.year}/')
            ]

            zip_file.extractall(self.save_folder, members=files_to_extract)

        print(f'Архив распакован в {self.save_folder}')

    @staticmethod
    def extract_severity(cve_data: Dict[str, Any]) -> Optional[float]:
        """Извлекает оценку cvss"""
        containers = cve_data.get('containers', {})

        for metric in containers.get('cna', {}).get('metrics', []):
            for version in CVSS_VERSIONS:
                if version in metric:
                    return float(metric[version]['baseScore'])

        for adp_container in containers.get('adp', []):
            for metric in adp_container.get('metrics', []):
                for version in CVSS_VERSIONS:
                    if version in metric:
                        return float(metric[version]['baseScore'])

        return None

    @staticmethod
    def extract_products(cve_data: Dict[str, Any]) -> Optional[str]:
        """Извлекает список затронутых ПО"""
        affected_list = (
            cve_data
            .get('containers', {})
            .get('cna', {})
            .get('affected', [])
        )

        product_names = [
            affected_item.get('product') or affected_item.get('packageName')
            for affected_item in affected_list
            if affected_item.get('product') or affected_item.get('packageName')
        ]

        return ", ".join(product_names) if product_names else None

    def parse_records(self) -> Tuple[List[CVE], int, int]:
        """Парсит файлы из папки и возвращает список объектов cve"""
        vulnerabilities = []
        no_severity = 0
        low_severity = 0

        for root_directory, _, filenames in os.walk(self.save_folder):
            for filename in filenames:
                if not filename.endswith('.json'):
                    continue

                file_path = os.path.join(root_directory, filename)

                with open(file_path, encoding='utf-8') as json_file:
                    cve_content = json.load(json_file)

                cve_list = (
                    cve_content
                    if isinstance(cve_content, list)
                    else [cve_content]
                )

                for cve_data in cve_list:
                    if not isinstance(cve_data, dict):
                        continue

                    cve_id = cve_data.get('cveMetadata', {}).get('cveId')
                    if not cve_id:
                        continue

                    severity_score = self.extract_severity(cve_data)
                    if severity_score is None:
                        no_severity += 1
                        continue

                    if severity_score < SEVERITY_LIMIT:
                        low_severity += 1
                        continue

                    descriptions = (
                        cve_data
                        .get('containers', {})
                        .get('cna', {})
                        .get('descriptions', [])
                    )
                    description = (
                        descriptions[0]['value']
                        if descriptions
                        else ''
                    )

                    published_date = (
                        cve_data
                        .get('cveMetadata', {})
                        .get('datePublished')
                    )
                    if published_date:
                        published_date = published_date.split('T')[0]

                    affected_products = self.extract_products(cve_data)

                    vulnerabilities.append(
                        CVE(
                            cve_id,
                            description,
                            severity_score,
                            published_date,
                            affected_products
                        )
                    )

        return vulnerabilities, no_severity, low_severity

    @staticmethod
    def save_to_db(vulnerabilities: List[CVE]):
        """Сохраняет cve в БД"""
        if not vulnerabilities:
            return

        connection = get_connection()
        cursor = connection.cursor()

        insert_query = """
            INSERT INTO vulnerabilities
            (cve_id, description, severity, published_date, source, affected_products)
            VALUES (%s, %s, %s, %s, %s, %s)
            ON CONFLICT (cve_id) DO NOTHING
        """

        for vulnerability in vulnerabilities:
            cursor.execute(
                insert_query,
                (
                    vulnerability.cve_id,
                    vulnerability.description,
                    vulnerability.severity,
                    vulnerability.published_date,
                    vulnerability.source,
                    vulnerability.affected_products
                )
            )

        connection.commit()
        cursor.close()
        connection.close()
