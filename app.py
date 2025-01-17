import json
import pymssql
from flask import Flask, jsonify, request
from flask_cors import CORS
from waitress import serve
import requests
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64
from cryptography.hazmat.primitives import padding
import logging
from logging.handlers import RotatingFileHandler





log_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
log_file = 'app.log'


log_handler = RotatingFileHandler(log_file, maxBytes=1000000, backupCount=5)
log_handler.setFormatter(log_formatter)

logger = logging.getLogger()
logger.setLevel(logging.DEBUG)
logger.addHandler(log_handler)


def decrypt_aes(ciphertext):
    key = b'my-secret-key-12'  # Frontend'den gönderilen AES key
    iv = b'my-fixed-iv-1234'
    ciphertext = base64.b64decode(ciphertext)

    # AES-CBC modunda bir şifreleme objesi oluşturuyoruz
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    try:
        # Şifreli veriyi deşifre ediyoruz
        decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

        # Padding kaldırma işlemi
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        decrypted_data = unpadder.update(decrypted_data) + unpadder.finalize()

        decrypted_text = decrypted_data.decode('utf-8')

        print(f"Decrypted text: {decrypted_text}")

        return decrypted_text

    except Exception as e:
        print(f"Decryption error: {str(e)}")
        return None


def connect_to_database(server, user, password, database):
    try:
        if not validate_ip(server):
            logger.warning(f'Invalid IP address entered: {server}')
            return None

        logger.info(f'Trying to connect to the database with IP: {server}')

        conn = pymssql.connect(
            server=server,
            user=user,
            password=password,
            database=database,
            as_dict=True
        )

        logger.info('Connection to the database was successful.')
        return conn

    except pymssql.OperationalError as e:
        logger.error(f'OperationalError: Could not connect to the database. Error: {str(e)}', exc_info=True)
        return jsonify("Could not connect to the database.")
    except Exception as e:
        logger.error(f'An unexpected error occurred: {str(e)}', exc_info=True)

    return None


def validate_ip(ip_address):
    # Basit bir IP doğrulama işlemi, daha gelişmiş bir doğrulama kullanılabilir
    import re
    pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
    if re.match(pattern, ip_address):
        return True
    else:
        return False


conn = connect_to_database(
    server='94.73.170.9',
    user='USR160420145114',
    password='PSSJi26Py57',
    database='DB160420145114',
    #as_dict=True
)



app = Flask(__name__)
# CORS(app)
CORS(app, resources={r"/*": {"origins": ["http://192.168.1.110:8091","http://192.168.1.110:8080"]}})



@app.route('/')
def hello_world():  # put application's code here
    return jsonify('Hello Tuğçe!')


@app.route('/register', methods=['POST'])
def register():
    try:
        person_id = request.form['ID']
        name = request.form['Ad']
        surname = request.form['Soyad']
        person_idnum = request.form['TCKN']
        birthday = request.form['Dogum_Tarihi']
        doc_num = request.form['Belge_Numarasi']
        birthloc = request.form['Dogum_Yeri']
        expiration_date = request.form['Son_Kullanim_Tarihi']
        gender = request.form['Cinsiyet']
        nation = request.form['Uyruk']
        other_names = ['Other_names']
        noh = request.form['NOH']
        pob = request.form['POB']
        address = request.form['Adres']
        image = request.form['IMAGE']
        cam_data = request.form['Cam_Data']


        if not (1 <= len(name) <= 20):
            raise ValueError("Ad en fazla 20 karakter içermelidir.")
        if not (1 <= len(surname) <= 35):
            raise ValueError("Soyad en fazla 35 karakter içermelidir.")

        if not (1 <= len(image) <= 16000):
            raise ValueError("image 16k olmalı")

        response = {
            # 'received_ID': person_id,
            'received_name': name,
            'received_surname': surname,
            'received_person_idnum': person_idnum,
            'received_birthday': birthday,
            'received_doc_num': doc_num,
            'received_birthloc': birthloc,
            'received_expiration_date': expiration_date,
            'received_gender': gender,
            'received_nation': nation,
            'received_other_names': other_names,
            'received_noh': noh,
            'received_pob': pob,
            'received_address': address,
            'received_image': image,
            'received_cam_data': cam_data
        }

    except KeyError as e:
        logger.error(f"Eksik anahtar:{str(e)}")
        return jsonify({"error": f"Eksik anahtar: {str(e)}"}), 400

    except ValueError as e:
        logger.error(str(e))

        return jsonify({"error": str(e)}), 400


    except Exception as e:
        logger.error(f"Genel hata:{str(e)}")
        return jsonify({"error": str(e)}, "type hatası yaptın dostum"), 500

    return jsonify(response)


@app.route('/insert', methods=['POST'])
def insert():
    try:
        encrypted_name = request.form['Ad']
        encrypted_surname = request.form['Soyad']
        encrypted_person_idnum = request.form['TCKN']
        encrypted_birthday = request.form['Dogum_Tarihi']
        encrypted_doc_num = request.form['Belge_Numarasi']
        encrypted_birthloc = request.form['Dogum_Yeri']
        encrypted_expiration_date = request.form['Son_Kullanim_Tarihi']
        encrypted_gender = request.form['Cinsiyet']
        encrypted_nation = request.form['Uyruk']
        encrypted_other_names = request.form['Other_names']
        encrypted_noh = request.form['NOH']
        encrypted_pob = request.form['POB']
        encrypted_address = request.form['Adres']
        encrypted_image = request.form['IMAGE']
        encrypted_cam_data = request.form['Cam_Data']

        name = decrypt_aes(encrypted_name)
        surname = decrypt_aes(encrypted_surname)
        person_idnum = decrypt_aes(encrypted_person_idnum)
        birthday = decrypt_aes(encrypted_birthday)
        doc_num = decrypt_aes(encrypted_doc_num)
        birthloc = decrypt_aes(encrypted_birthloc)
        expiration_date = decrypt_aes(encrypted_expiration_date)
        gender = decrypt_aes(encrypted_gender)
        nation = decrypt_aes(encrypted_nation)
        other_names = decrypt_aes(encrypted_other_names)
        noh = decrypt_aes(encrypted_noh)
        pob = decrypt_aes(encrypted_pob)
        address = decrypt_aes(encrypted_address)
        image = decrypt_aes(encrypted_image)
        cam_data = decrypt_aes(encrypted_cam_data)

        if not name or not surname or not birthday or not birthloc or not gender:
            return jsonify({"error": "Gerekli bilgiler eksik"}), 400

        facematch_response = facematch(person_idnum, cam_data)

        if not facematch_response:
            logger.error("Facematch API yanıtı alınamadı.")
            return jsonify({"error": "Facematch API yanıtı alınamadı."}), 500

        eslesme_sonucu = facematch_response["eslesmeSonucu"]
        skor = facematch_response["skor"]
        facematch_id = facematch_response["id"]

        cursor = conn.cursor()

        try:
            SQL_QUERY = """INSERT INTO KimlikBilgisi 
                       (Ad, Soyad, TCKN, Dogum_Tarihi, Belge_Numarasi, Dogum_Yeri, Son_Kullanim_Tarihi, 
                       Cinsiyet, Uyruk, Other_names, NOH, POB, Adres, IMAGE, Cam_Data, DB_ID) 
                       VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"""

            cursor.execute(SQL_QUERY, (encrypted_name, encrypted_surname, encrypted_person_idnum,
                                       encrypted_birthday, encrypted_doc_num, encrypted_birthloc,
                                       encrypted_expiration_date, encrypted_gender, encrypted_nation,
                                       encrypted_other_names, encrypted_noh, encrypted_pob, encrypted_address,
                                       encrypted_image, encrypted_cam_data, facematch_id))
            conn.commit()

            SQL_INSERT_SONUC = """INSERT INTO Sonuc 
                                  (id, isim, skor, eslesmeSonucu) 
                                  VALUES (%s, %s, %s, %s)"""

            cursor.execute(SQL_INSERT_SONUC, (facematch_id, name, skor, eslesme_sonucu))
            conn.commit()

        except Exception as e:
            conn.rollback()
            logger.error(f"Veritabanı hata: {str(e)}")
            return jsonify({"error": f"Veritabanına eklenemedi: {str(e)}"}), 500

        return facematch_response

    except Exception as e:
        logger.error(f"Genel hata: {str(e)}")
        return jsonify({"error": f"Beklenmeyen hata,facematch bağlantısı olmayabilir.: {str(e)}"}), 500


## tuğçeeeeeee



# Logger yapılandırması
logging.basicConfig(level=logging.ERROR)
logger = logging.getLogger(__name__)

def facematch(person_idnum, cam_data):
    url = 'http://herenbas.com/sfapi/FaceMatch'
    data = {
        'TCKN': person_idnum,
        'b_64_image': cam_data
    }

    headers = {
        'Authorization': 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYmYiOjE3MjQyNDY5NjAsImV4cCI6MTcyOTQzMDk2MCwiaXNzIjoiS29kZGEgWWF6xLFsxLFtICIsImF1ZCI6Ind3dy5oZXJlbmJhcy5jb20ifQ.6nvzdq_gvP35VUW-JTtZjowXjbYr5aesSeXGPXi88OY'
    }

    try:
        response = requests.post(url, headers=headers, data=data)
        response.raise_for_status()

        # HTTP 200 başarılı ise, yanıtı işlemeye başla
        response_json = response.json()
        formatted_response = {
            "id": response_json.get("id", "N/A"),
            "isim": response_json.get("isim", ""),
            "skor": response_json.get("skor", "0.0"),
            "eslesmeSonucu": "True" if response_json.get("eslesmeSonucu") else "False"
        }
        return formatted_response

    except ValueError:
        logger.error("Yanıt JSON formatında değil.")
        return jsonify({"error": "Yanıt JSON formatında değil."}), 500

    except requests.HTTPError as http_err:
        logger.error(f"HTTP hatası: {http_err}")
        return jsonify({"error": f"HTTP hatası: {http_err}"}), response.status_code

    except requests.RequestException as req_err:
        logger.error(f"HTTP isteği hatası: {req_err}")
        return jsonify({"error": f"HTTP isteği hatası: {req_err}"}), 500

    except Exception as err:
        logger.error(f"Beklenmedik hata: {err}")
        return jsonify({"error": f"Beklenmedik hata: {err}"}), 500



@app.route('/read', methods=['POST'])
def read():
    try:
        SQL_QUERY = """select * from KimlikBilgisi"""
        cursor = conn.cursor()
        cursor.execute(SQL_QUERY)
        records = cursor.fetchall()
        veriler = json.dumps(records)
        return veriler


    except Exception as e:
        logger.error(f"Veri okuma hata: {str(e)}")
        print(f"error occurred: {str(e)}")
        return jsonify({"error": f"Internal Server Error,Read Route çalışmıyor:{str(e)}"})

@app.route('/get_user_info', methods=['POST'])
def get_user_info():

    try:
        # Kullanıcıdan gelen TCKN'yi alın
        person_idnum = request.json.get('TCKN')
        print(f"tckn:{person_idnum}")

        # TCKN'ye göre veritabanından bilgileri çekmek için SQL sorgusu
        SQL_QUERY = """SELECT * FROM KimlikBilgisi WHERE TCKN = %s """

        cursor = conn.cursor()
        cursor.execute(SQL_QUERY, (person_idnum,))
        user_data = cursor.fetchone()  # Veritabanından tek bir kayıt çekiliyor

        # Eğer kullanıcı bulunamazsa
        if not user_data:
            logger.warning(f"Kullanıcı bulunamadı: {person_idnum}")
            return jsonify({"error": "Kullanıcı bulunamadı"}), 404

        # Kullanıcı bilgilerini JSON formatında döndürme
        return jsonify(user_data)

    except Exception as e:
        logger.error(f"Genel hata: {str(e)}")
        print(f"Error occurred: {str(e)}")
        return jsonify({"error": "Internal Server Error,Kullanıcı bilgileri alınamıyor!"}), 500



@app.route('/update', methods=['POST'])
def update():
    try:
        new_person_id = request.form['ID']
        new_name = request.form['Ad']
        new_surname = request.form['Soyad']
        new_person_idnum = request.form['TCKN']
        new_birthday = request.form['Dogum_Tarihi']
        new_doc_num = request.form['Belge_Numarasi']
        new_birthloc = request.form['Dogum_Yeri']
        new_expiration_date = request.form['Son_Kullanim_Tarihi']
        new_gender = request.form['Cinsiyet']
        new_nation = request.form['Uyruk']
        new_other_names = request.form['Other_names']
        new_noh = request.form['NOH']
        new_pob = request.form['POB']
        new_address = request.form['Adres']
        new_image = request.form['IMAGE']
        new_cam_data = request.form['Cam_Data']
        new_facematch_id = request.form['facematch_id']

        if not new_person_id:
            logger.warning("Güncellenecek alan belirtilmemiş")
            return jsonify({"error": "ID eksik"}), 400

        SQL_QUERY = """UPDATE Tablo SET """

        update_fields = []
        update_values = []

        if new_person_id:
            update_fields.append("ID = %s")
            update_values.append(new_person_id)

        if new_name:
            update_fields.append("Ad = %s")
            update_values.append(new_name)

        if new_surname:
            update_fields.append("Soyad = %s")
            update_values.append(new_surname)

        if new_person_idnum:
            update_fields.append("TCKN = %s")
            update_values.append(new_person_idnum)

        if new_birthday:
            update_fields.append("Dogum_Tarihi = %s")
            update_values.append(new_birthday)

        if new_doc_num:
            update_fields.append("Belge_Numarasi = %s")
            update_values.append(new_doc_num)

        if new_birthloc:
            update_fields.append("Dogum_Yeri = %s")
            update_values.append(new_birthloc)

        if new_expiration_date:
            update_fields.append("Son_Kullanim_Tarihi = %s")
            update_values.append(new_expiration_date)

        if new_gender:
            update_fields.append("Cinsiyet = %s")
            update_values.append(new_gender)

        if new_nation:
            update_fields.append("Uyruk = %s")
            update_values.append(new_nation)

        if new_other_names:
            update_fields.append("Other_names = %s")
            update_values.append(new_other_names)

        if new_noh:
            update_fields.append("NOH = %s")
            update_values.append(new_noh)

        if new_pob:
            update_fields.append("POB = %s")
            update_values.append(new_pob)

        if new_address:
            update_fields.append("Adres = %s")
            update_values.append(new_address)

        if new_image:
            update_fields.append("IMAGE = %s")
            update_values.append(new_image)

        if new_cam_data:
            update_fields.append("Cam_Data = %s")
            update_values.append(new_cam_data)

        if new_facematch_id:
            update_fields.append("facematch_id = %s")
            update_values.append(new_facematch_id)

        if not update_fields:
            return jsonify({"error": "Güncellenecek alan belirtilmemiş"}), 400

        if new_cam_data:
            update_fields.append("Cam_Data = %s")
            update_values.append(new_cam_data)

        if new_facematch_id:
            update_fields.append("facematch_id = %s")
            update_values.append(new_facematch_id)

        SQL_QUERY += ", ".join(update_fields)
        SQL_QUERY += " WHERE ID = %s"

        update_values.append(new_person_id)

        cursor = conn.cursor()
        cursor.execute(SQL_QUERY, update_values)
        conn.commit()
        return jsonify("oldu")


    except Exception as e:
        logger.error(f"Güncelleme hata: {str(e)}")
        print(f"Error occurred: {str(e)}")
        return jsonify({"error,Güncelleme hata!": str(e)}), 500


@app.route('/delete', methods=['POST'])
def delete():
    try:

        delete_person_ID = request.form['ID']

        if not delete_person_ID:
            logger.warning("ID eksik")
            return jsonify({"error": "ID eksik"}), 400

        SQL_QUERY = "DELETE FROM Tablo WHERE ID = %s"

        cursor = conn.cursor()
        cursor.execute(SQL_QUERY, (delete_person_ID,))
        conn.commit()

        return jsonify({"message": "silindi"})

    except Exception as e:
        logger.error(f"Silme hata: {str(e)}")
        print(f"Error occurred: {str(e)}")
        return jsonify({"error,Silme işlemi hata!": str(e)}), 500


@app.route('/soap_request', methods=['POST'])
def soap_request():
    try:
        # İstekten verileri al
        tc_no = request.form.get('TCKimlikNo')
        ad = request.form.get('Ad')
        soyad = request.form.get('Soyad')
        dogum_yili = request.form.get('DogumYili')

        # Eksik veri kontrolü
        if not tc_no or not ad or not soyad or not dogum_yili:
            raise ValueError("Tüm alanlar doldurulmalıdır: TCKimlikNo, Ad, Soyad, DogumYili.")

        # Web servisi URL'si
        url = 'https://tckimlik.nvi.gov.tr/Service/KPSPublic.asmx'

        # SOAP isteği XML formatında
        soap_request = f'''<?xml version="1.0" encoding="utf-8"?>
        <soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:ws="http://tckimlik.nvi.gov.tr/WS">
           <soap:Header/>
           <soap:Body>
              <ws:TCKimlikNoDogrula>
                 <ws:TCKimlikNo>{tc_no}</ws:TCKimlikNo>
                 <ws:Ad>{ad}</ws:Ad>
                 <ws:Soyad>{soyad}</ws:Soyad>
                 <ws:DogumYili>{dogum_yili}</ws:DogumYili>
              </ws:TCKimlikNoDogrula>
           </soap:Body>
        </soap:Envelope>'''

        # SOAP isteği gönderme
        headers = {
            'Content-Type': 'application/soap+xml; charset=utf-8',  # SOAP 1.2'ye göre Content-Type
            'SOAPAction': 'http://tckimlik.nvi.gov.tr/WS/TCKimlikNoDogrula'  # SOAPAction, web servisi dokümantasyonunda belirtilir
        }

        response = requests.post(url, data=soap_request, headers=headers)

        # HTTP isteği başarılı olmadıysa
        if response.status_code != 200:
            logger.error(f"SOAP isteği başarısız: {response.status_code} - {response.text}")
            return jsonify({'error': f"SOAP isteği başarısız oldu. Status Code: {response.status_code}"}), 500

        # Yanıtı kontrol etme
        response_text = response.text
        if 'TCKimlikNoDogrulaResult>true</TCKimlikNoDogrulaResult>' in response_text:
            result = True
        else:
            result = False

        return jsonify({'result': result})

    except requests.exceptions.RequestException as e:
        logger.error(f"SOAP isteği sırasında ağ hatası: {str(e)}", exc_info=True)
        return jsonify({'error': "Ağ hatası meydana geldi. Lütfen daha sonra tekrar deneyin."}), 500

    except ValueError as ve:
        logger.error(f"Geçersiz giriş hatası: {str(ve)}", exc_info=True)
        return jsonify({'error,Geçersiz giriş hatası': str(ve)}), 400

    except Exception as e:
        logger.error(f"Beklenmeyen bir hata oluştu: {str(e)}", exc_info=True)
        return jsonify({'error': "SOAP REQUEST!Beklenmeyen bir hata oluştu. Lütfen tekrar deneyin."}), 500



if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=9099)

serve(app, host='192.168.1.158', port='9099', threads=5)