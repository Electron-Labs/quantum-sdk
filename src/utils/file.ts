import fs from "fs";

export function checkIfPathExist(folderPath: string) {
    return fs.existsSync(folderPath)
}

export function checkPathAndReadJsonFile(filePath: string) {
    let isPathExist = checkIfPathExist(filePath);
    if(!isPathExist) {
        throw new Error(`filePath does not exist : ${filePath}.`);
    }
    return readJsonFile(filePath);
}

export function createFolder(fodlerPath: string) {
    return fs.mkdirSync(fodlerPath);
}

export function deleteFolder(fodlerPath: string) {
    fs.rmSync(fodlerPath, { recursive: true, force: true });
}

export function createFile(path: string, data: Object) {
    fs.writeFileSync(path, JSON.stringify(data, (_, v) => typeof v === 'bigint' ? v.toString() : v, 2));
}

export function readJsonFile(path: string) {
    try {
        const data = fs.readFileSync(path, 'utf8');
        const jsonData = JSON.parse(data);
        return jsonData;
    } catch(e) {
        throw new Error(`Error reading or parsing JSON file path ${path} : ${e}`);
    }
}