/*
    SteroidCrypto class

    getSkey
    gives skey for the password in order to make it unpredictable
    
    SteroidCrypto.getSkey(raw password) => number (dec ~2^32)

    messageEnc
    encrypts or decripts the messages in main chat app

    messageEnc(message, password, bool)
        password - hex (as a standard)
        if bool == true  =>     encrypts message
        if bool == false =>     decrypts message 

        if success
            {
                s:1,
                t:text,
                v:0
            }
        else
            {
                s:0,
                t:text, // error, just "error"
                v:0
            }

    
    getPass
    gets hash from low entrophy password

    getPass(password)
        password - raw input => hex 256bit



    genPair 
    Generates Key Pair for RSA
    genPair(*bitKeySize) => 4k by default
        {
            s: true/false // as status if it was successfull
            e: erroe message IF error exist
            r: response { //if error => null
                            publicKey: base 64 from the key
                            privateKey: base 64 from the key
                        }
        }


    createPackage
    Creates ready to send package from the sender
    createPackage(publicKeyBase64, hexString (signature from server in hex))
        {
            s: true,                            //status true/false
            e: 0,                               // error message if exits
            salt: salt,                         // hex string -> have to be saved localy for later validation
            r: {                                // responce body (fully ready to be sent)
                publicKey: publicKeyBase64,     // public key in base64
                originSha: hexString,           // hexString from sever
                signature: signature            // signature
            }
        }

    prevalidator
    prevalidator(createPackage.r, inputString) 
    inputString - hex 64 char original string from the server
    Checks if all the data is correct when recived
    {
        s: true,                            //status true/false
        e: 0,                               // error message if exits
        r: createPackage.r
    }



*/
class SteroidCrypto {
    constructor() {
    }

    async getSkey (password) {
        // Локальные функции для хэширования
        const hash = async (algo, data) => {
            const encoder = new TextEncoder();
            const buffer = encoder.encode(data);
            const hashBuffer = await crypto.subtle.digest(algo, buffer);
            return new Uint8Array(hashBuffer);
        };

        // PBKDF2 функция
        const deriveKey = async (passwordHash, salt, iterations, hash) => {
            const baseKey = await crypto.subtle.importKey(
                "raw",
                passwordHash,
                {name: "PBKDF2"},
                false,
                ["deriveBits"]
            );
            return await crypto.subtle.deriveBits(
                {
                    name: "PBKDF2",
                    salt: salt,
                    iterations: iterations,
                    hash: hash,
                },
                baseKey,
                256 // Вывод в битах
            );
        };

        const pseudoHash = async (input) => {
            let sum = 0;
            for (let i = 0; i < input.length; i++) {
              sum += input.charCodeAt(i);
            }
            return sum;
        };

        const extractBits = async (key1, key2) => {
            // Получаем псевдо-хеш для key2
            const hashValue = await pseudoHash(key2);
            
            // Вычисляем стартовый индекс в битах
            const startIndex = hashValue % (256 - 32); // 256 бит в key1 и нужно 32 бита
            
            // Конвертируем key1 из hex в бинарный вид
            let key1Binary = '';
            for (let i = 0; i < key1.length; i += 2) {
              key1Binary += parseInt(key1.substring(i, i + 2), 16).toString(2).padStart(8, '0');
            }
            
            // Извлекаем 32 бита начиная с вычисленного индекса
            const extractedBits = key1Binary.substring(startIndex, startIndex + 32);
            
            // Возвращаем извлеченные биты в hex
            return parseInt(extractedBits, 2).toString(16).padStart(8, '0');
        };

        // Получение хешей пароля
        const sha256Password = await hash('SHA-256', password);
        const sha512Password = await hash('SHA-512', password);

        // Преобразование Uint8Array в hex строку
        const toHexString = bytes => bytes.reduce((str, byte) => str + byte.toString(16).padStart(2, '0'), '');

        // Получение ключей через PBKDF2
        const key1Bytes = await deriveKey(sha256Password, sha512Password, 10000, 'SHA-256');
        const key2Bytes = await deriveKey(sha512Password, sha256Password, 1000, 'SHA-512');

        const key1Hex = toHexString(new Uint8Array(key1Bytes));
        const key2Hex = toHexString(new Uint8Array(key2Bytes));

        // Исправлен вызов extractBits и его обработка
        const bits = await extractBits(key1Hex, key2Hex);
        return parseInt(bits, 16);
    };

    async messageEnc(text, password, isEncrypt, algo = 0) {
        try {
            if (isEncrypt) {
                const salt = crypto.getRandomValues(new Uint8Array(32));
                const iv = crypto.getRandomValues(new Uint8Array(12));
                const keyMaterial = await crypto.subtle.importKey(
                    "raw",
                    new TextEncoder().encode(password),
                    { name: "PBKDF2" },
                    false,
                    ["deriveBits", "deriveKey"]
                );
                const key = await crypto.subtle.deriveKey(
                    {
                        name: "PBKDF2",
                        salt: salt,
                        iterations: 100,
                        hash: "SHA-256"
                    },
                    keyMaterial,
                    { name: "AES-GCM", length: 256 },
                    false,
                    ["encrypt"]
                );
                const encrypted = await crypto.subtle.encrypt(
                    { name: "AES-GCM", iv: iv },
                    key,
                    new TextEncoder().encode(text)
                );
                const encryptedBuffer = new Uint8Array(encrypted);
                const resultBuffer = new Uint8Array(salt.length + iv.length + encryptedBuffer.length);
                resultBuffer.set(salt, 0);
                resultBuffer.set(iv, salt.length);
                resultBuffer.set(encryptedBuffer, salt.length + iv.length);
                return {
                    s: 1,
                    t: resultBuffer, // возвращаем как Uint8Array
                    v: algo
                };
            } else {
                // Важно: 'text' должен быть Uint8Array при расшифровке
                const salt = text.slice(0, 32);
                const iv = text.slice(32, 44);
                const encrypted = text.slice(44);
                const keyMaterial = await crypto.subtle.importKey(
                    "raw",
                    new TextEncoder().encode(password),
                    { name: "PBKDF2" },
                    false,
                    ["deriveBits", "deriveKey"]
                );
                const key = await crypto.subtle.deriveKey(
                    {
                        name: "PBKDF2",
                        salt: salt,
                        iterations: 100,
                        hash: "SHA-256"
                    },
                    keyMaterial,
                    { name: "AES-GCM", length: 256 },
                    false,
                    ["decrypt"]
                );
                const decrypted = await crypto.subtle.decrypt(
                    { name: "AES-GCM", iv: iv },
                    key,
                    encrypted
                );
                return {
                    s: 1,
                    t: new TextDecoder().decode(decrypted),
                    v: algo
                };
            }
        } catch (error) {
            console.error("Ошибка при шифровании/расшифровке:", error);
            return {
                s: 0,
                t: "error",
                v: algo
            };
        }
    }


    async getPass(password) {
        // Хэширование пароля с использованием SHA-512 для создания соли
        const getSalt = async (password) => {
            const encoder = new TextEncoder();
            const data = encoder.encode(password);
            const hashBuffer = await crypto.subtle.digest('SHA-512', data);
            return new Uint8Array(hashBuffer);
        };

        const salt = await getSalt(password);
        
        // Импорт пароля как ключа для PBKDF2
        const keyMaterial = await crypto.subtle.importKey(
            "raw",
            new TextEncoder().encode(password),
            { name: "PBKDF2" },
            false,
            ["deriveBits", "deriveKey"]
        );

        // Производный ключ с использованием PBKDF2
        const derivedKey = await crypto.subtle.deriveKey(
            {
                name: "PBKDF2",
                salt: salt,
                iterations: 1000000,
                hash: 'SHA-512'
            },
            keyMaterial,
            { name: "HMAC", hash: "SHA-512", length: 512 }, // Параметры не имеют большого значения для deriveBits
            true,
            ["verify"] // Права не имеют значения, так как ключ не будет использоваться для HMAC
        );

        // Получение битов ключа
        const derivedBits = await crypto.subtle.exportKey("raw", derivedKey);
        const keyBuffer = new Uint8Array(derivedBits);

        // Конвертация битов ключа в hex строку
        return Array.from(keyBuffer).map(byte => byte.toString(16).padStart(2, '0')).join('');
    }

////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////CHANGE HERE////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////    

// Добавляем метод genPair для генерации пары ключей RSA
async genPair(keySize = 4096) {
    const generateKeyPair = async (keySize) => {
        // Генерация пары ключей с заданными параметрами
        return await crypto.subtle.generateKey(
            {
                name: "RSA-OAEP",
                modulusLength: keySize,       // Длина ключа в битах, по умолчанию 4096
                publicExponent: new Uint8Array([1, 0, 1]),  // Обычно 65537, что равно 0x010001
                hash: {name: "SHA-256"},      // Алгоритм хеширования
            },
            true,   // ключи должны быть экспортируемыми
            ["encrypt", "decrypt"]  // возможности использования ключей
        );
    };

    try {
        const keyPair = await generateKeyPair(keySize);
        // Экспорт ключей в формате специфичном для Web Crypto API
        const publicKey = await crypto.subtle.exportKey("spki", keyPair.publicKey);
        const privateKey = await crypto.subtle.exportKey("pkcs8", keyPair.privateKey);

        // Преобразование ключей в строковый формат для удобства отображения
        const toBase64 = buffer => window.btoa(String.fromCharCode(...new Uint8Array(buffer)));

        return {
            s: true,
            e: null,
            r: {
                publicKey: toBase64(publicKey),
                privateKey: toBase64(privateKey)
            }
        };
    } catch (error) {
        console.error("Ошибка генерации ключей RSA:", error);
        return {
            s: false,
            e: error.message,
            r: null
        };
    }
}

async createPackage(publicKeyBase64, hexString) {
    try {
        // Генерация случайной соли
        const saltBytes = crypto.getRandomValues(new Uint8Array(32)); // 32 байта => 64 символа в hex
        const salt = Array.from(saltBytes).map(b => b.toString(16).padStart(2, '0')).join('');

        // Создание SHA-512 хеша
        const encoder = new TextEncoder();
        const dataToHash = encoder.encode(publicKeyBase64 + hexString + salt);
        const hashBuffer = await crypto.subtle.digest('SHA-512', dataToHash);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        const signature = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');

        // Формирование ответа
        return {
            s: true,
            e: 0,
            salt: salt,
            r: {
                publicKey: publicKeyBase64,
                originSha: hexString,
                signature: signature
            }
        };
    } catch (error) {
        return {
            s: false,
            e: error.message,
            salt: null,
            r: null
        };
    }
}

async prevalidator(receivedObj, inputString) {
    try {
        // Проверка длины входной строки (она должна быть равна длине hex SHA-256 хеша)
        if (inputString.length !== 64) {
            throw new Error("Некорректная длина входной строки");
        }

        // Регулярное выражение для проверки, что строка является корректной hex-строкой
        const hexRegex = /^[a-fA-F0-9]+$/;
        if (!hexRegex.test(inputString)) {
            throw new Error("Входная строка содержит недопустимые символы");
        }

        // Валидация publicKey с использованием регулярного выражения для base64
        const base64Regex = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
        if (!base64Regex.test(receivedObj.publicKey)) {
            throw new Error("Публичный ключ имеет некорректный формат");
        }

        // Валидация signature, должен быть hex-строкой
        const signatureHexRegex = /^[a-fA-F0-9]+$/;
        if (!signatureHexRegex.test(receivedObj.signature)) {
            throw new Error("Подпись имеет некорректный формат");
        }

        // Вычисление SHA-256 хеша для входной строки
        const encoder = new TextEncoder();
        const dataToHash = encoder.encode(inputString);
        const hashBuffer = await crypto.subtle.digest('SHA-256', dataToHash);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        const calculatedSha = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');

        // Сравнение полученного хеша с originSha из объекта
        if (calculatedSha !== receivedObj.originSha) {
            throw new Error("Хеш входной строки не совпадает с ожидаемым originSha");
        }

        // Проверка, что все необходимые поля присутствуют в receivedObj
        if (!receivedObj.publicKey || !receivedObj.signature) {
            throw new Error("Объект не содержит всех необходимых полей");
        }

        // Все проверки пройдены
        return {
            s: true,
            e: 0,
            r: receivedObj
        };
    } catch (error) {
        return {
            s: false,
            e: error.message,
            r: null
        };
    }
}





////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////

}

(() => {
    window.SteroidCrypto = SteroidCrypto;
})()


//TODO create redax for all 