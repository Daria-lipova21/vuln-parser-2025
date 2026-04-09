from mitre import MITREParser, ZIP_URL, YEAR as MITRE_YEAR, SAVE_FOLDER
from msrc import MSRCParser, Database, YEAR as MSRC_YEAR, SEVERITY_LIMIT
from dotenv import load_dotenv
load_dotenv()


def run_mitre():
    mitre_parser = MITREParser(ZIP_URL, MITRE_YEAR, SAVE_FOLDER)
    mitre_parser.download_and_extract()
    vulnerabilities, no_severity, low_severity = mitre_parser.parse_records()
    mitre_parser.save_to_db(vulnerabilities)

    print(
        f'MITRE\n'
        f'Пропущено CVE без оценки критичности: {no_severity}\n'
        f'Пропущено CVE с низкой критичностью: {low_severity}\n'
        f'Сохранено в БД: {len(vulnerabilities)}'
    )

def run_msrc():
    msrc_parser = MSRCParser(MSRC_YEAR, SEVERITY_LIMIT)
    msrc_parser.run()
    db = Database(msrc_parser.vulnerabilities)
    saved_count = db.save()

    print(
        f'MSRC\n'
        f'Пропущено CVE без оценки критичности: {msrc_parser.no_severity}\n'
        f'Пропущено CVE с низкой критичностью: {msrc_parser.low_severity}\n'
        f'Сохранено в БД: {saved_count}'
    )

if __name__ == '__main__':
    run_mitre()
    run_msrc()