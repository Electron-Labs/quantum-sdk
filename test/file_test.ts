import { describe } from "mocha";
import * as fileFunctions from "../src/utils/file";
import {assert, expect} from "chai";
import * as fs from 'fs';

describe("file existence test", () =>{
    it("checking file existence for correct path",() => {
        let correctPath:string = "src/quantum_helper.ts";
        let exist = fileFunctions.checkIfPathExist(correctPath);
        expect(exist).to.equal(true);       
    });

    it("checking file existence for incorrect path",() => {
        let incorrectPath:string = "src/random.ts";
        let exist = fileFunctions.checkIfPathExist(incorrectPath);
        expect(exist).to.equal(false);       
    });
});

describe("file read test", ()=>{
    it("reading file from correct path", () => {
        let correctPath:string = "test/dump/snark/circuit/2/input.json";
        try {
            fileFunctions.checkPathAndReadJsonFile(correctPath);
        }
        catch(error){
            throw new Error("Unable to from correct path");
        }
    });

    it("reading file from incorrect path", () => {
        let incorrectPath:string = "test/dump/snark/circuit/2/random.json";
        expect(() => fileFunctions.checkPathAndReadJsonFile(incorrectPath))
        .to.throw(`filePath does not exist : ${incorrectPath}.`);
    });
});

describe("reading and parsing JSON file", () => {
    it("should read json and parse json", () => {
        let correctPath:string = "test/dump/snark/circuit/2/input.json";
        try {
            fileFunctions.readJsonFile(correctPath);
        }
        catch(e){
            throw new Error("unable to read JSON");
        }
    });
    it("should throw error, correct path but not json", () => {
        let correctPathWrongFile = "test/dump/snark/circuit/1/program/multiplier.circom";
        try {
           fileFunctions.readJsonFile(correctPathWrongFile);
        }
        catch(error: any){
            expect(error.message).to.include(`Error reading or parsing JSON file path ${correctPathWrongFile}`);
        }
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
        try {
            fileFunctions.createFile(testFilePath, data);
            const fileContent = fs.readFileSync(testFilePath, 'utf8');
            expect(fileContent).to.equal(JSON.stringify(data, (_, v) => typeof v === 'bigint'? v.toString() : v, 2));
        } catch (error) {
            throw new Error('Failed to create file');
        }
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
        try {
            // folder creation
            fileFunctions.createFolder(folderName);
            expect(fs.existsSync(folderName)).to.be.true;
        }
        catch(error: any){
            throw new Error("Unable to create new folder");
        }
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
        try {
            fileFunctions.deleteFolder(folderName);
            expect(fs.existsSync(folderName)).to.be.false;
        }
        catch {
            throw new Error("Unable to delete folder");
        }
    });

});
