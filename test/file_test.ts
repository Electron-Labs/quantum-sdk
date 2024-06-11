import { describe } from "mocha";
import * as fileFunctions from "../src/utils/file";
import {assert, expect} from "chai";
import * as fs from 'fs';

describe("file existence test", () =>{
    it("should return true for correct path",() => {
        let correctPath:string = "src/quantum_helper.ts";
        let exist = fileFunctions.checkIfPathExist(correctPath);
        expect(exist).to.equal(true);       
    });

    it("should return false for incorrect path",() => {
        let incorrectPath:string = "src/random.ts";
        let exist = fileFunctions.checkIfPathExist(incorrectPath);
        expect(exist).to.equal(false);       
    });
});

describe("file read test", ()=>{
    it("should pass when reading from correct path", () => {
        let correctPath:string = "test/dump/snark/circuit/2/input.json";
        let res = fileFunctions.checkPathAndReadJsonFile(correctPath);
        expect(res).to.be.ok;
    });

    it("should fail when reading from incorrect path", () => {
        let incorrectPath:string = "test/dump/snark/circuit/2/random.json";
        expect(() => fileFunctions.checkPathAndReadJsonFile(incorrectPath))
        .to.throw(`filePath does not exist : ${incorrectPath}.`);
    });
});

describe("reading and parsing JSON file", () => {
    it("should read json and parse json", () => {
        let correctPath:string = "test/dump/snark/circuit/2/input.json";
        let res = fileFunctions.readJsonFile(correctPath);
        expect(res).to.be.ok;
    });
    it("should throw error, correct path but not json", () => {
        let correctPathWrongFile = "test/dump/snark/circuit/1/program/multiplier.circom";
        expect(()=>{fileFunctions.readJsonFile(correctPathWrongFile)}).to.throw(`Error reading or parsing JSON file path ${correctPathWrongFile}`)     
    })
});

describe('file creation test', () => {
    const tempDir = './tempFiles';
    const testFilePath = `${tempDir}/testFile.json`;
    const data = { key: 'value', bigIntValue: BigInt(1234567890123456789012345678901234567890) };

    beforeEach(() => {
        if (!fs.existsSync(tempDir)) {
            fs.mkdirSync(tempDir, { recursive: true });
        }
    });

    afterEach(() => {
        if (fs.existsSync(tempDir)) {
            fs.readdirSync(tempDir).forEach(file => {
                fs.unlinkSync(`${tempDir}/${file}`);
            });
            fs.rmdirSync(tempDir, { recursive: true });
        }
    });

    it('should successfully create a file with JSON data', () => {
        fileFunctions.createFile(testFilePath, data);
        const fileContent = fs.readFileSync(testFilePath, 'utf8');
        expect(fileContent).to.equal(JSON.stringify(data, (_, v) => typeof v === 'bigint'? v.toString() : v, 2));
    });

    it("should fail when given invalid file path", function() {
        let invalidPath = "./invalid/path.json";
        expect(() => fileFunctions.createFile(invalidPath, data)).to.throw(/ENOENT: no such file or directory*/);
    });
});

describe("folder creation test", () => {
    let folderName: string = "./test_creation";

    afterEach(() => {
        if(fs.existsSync(folderName)){ 
            fs.rmdirSync(folderName);
        }
    });

    it("should successfully create folder", () => {
        fileFunctions.createFolder(folderName);
        expect(fs.existsSync(folderName)).to.be.true;
    });
});


describe("folder deletion test", () => {
    let folderName:string = "./test_deletion" 

    beforeEach(() => {
        fs.mkdirSync(folderName);
    });

    // After Each is Added in case the function tested cannot delete
    // file and threw some error

    afterEach(() => {
        if (fs.existsSync(folderName)){
            fs.rmdirSync(folderName);
        }
    });

    it("should successfully delete the folder", () => {
        fileFunctions.deleteFolder(folderName);
        expect(fs.existsSync(folderName)).to.be.false;
    });

});
