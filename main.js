class SteroidCrypto {
    constructor() {
        console.log('SteroidCrypto инициализирован');
    }

    getSkey = async (password) => {
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
}
