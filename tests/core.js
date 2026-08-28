import { LPCore } from "../core.js";
let LPC = new LPCore("SuperSecretStaticSecret","abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%&*?-_.+")

// ---

let passedTests = 0
let totalTests = 0

// ---

// General functionality test - same inputs should yield same output across updates
totalTests += 1
let output = await LPC.getPW("lesserpass.org","LPUser@lesserpass.org","MyAwesomeSecurePassword!",0,16,true,true,true,true)
if (output == "2WM-2q#Keyqok8i.") {
    passedTests += 1
}

// Deterministic test - same inputs should yield same output
totalTests += 1
let deter1 = await LPC.getPW("lesserpass.org","DETERMINED","MyAwesomeSecurePassword",0,16,true,true,true,true)
let deter2 = await LPC.getPW("lesserpass.org","DETERMINED","MyAwesomeSecurePassword",0,16,true,true,true,true)
if (deter1 == deter2) {
    passedTests += 1
}

// Test for password lengths (including invalid lengths)
totalTests += 1
let lengthNeg10 = await LPC.getPW("lesserpass.org","LENGTH","MyAwesomeSecurePassword",0,-10,true,true,true,true)
let length0 = await LPC.getPW("lesserpass.org","LENGTH","MyAwesomeSecurePassword",0,0,true,true,true,true)
let length4 = await LPC.getPW("lesserpass.org","LENGTH","MyAwesomeSecurePassword",0,4,true,true,true,true)
let length8 = await LPC.getPW("lesserpass.org","LENGTH","MyAwesomeSecurePassword",0,8,true,true,true,true)
let length16 = await LPC.getPW("lesserpass.org","LENGTH","MyAwesomeSecurePassword",0,16,true,true,true,true)
let length32 = await LPC.getPW("lesserpass.org","LENGTH","MyAwesomeSecurePassword",0,32,true,true,true,true)
let length64 = await LPC.getPW("lesserpass.org","LENGTH","MyAwesomeSecurePassword",0,64,true,true,true,true)
let length128 = await LPC.getPW("lesserpass.org","LENGTH","MyAwesomeSecurePassword",0,128,true,true,true,true)
let length256 = await LPC.getPW("lesserpass.org","LENGTH","MyAwesomeSecurePassword",0,256,true,true,true,true)
if (lengthNeg10 == ""
    && length0 == ""
    && length4.length == 4
    && length8.length == 8
    && length16.length == 16
    && length32.length == 32
    && length64.length == 64
    && length128.length == 128
    && length256.length == 256) {
    passedTests += 1
}

// Category tests - ensure that the password contains at least one character from each selected category
// includeLowerCase, includeUpperCase, includeNumbers, includeSymbols

// 0000 - Nothing enabled
totalTests += 1
let Test0000 = await LPC.getPW("lesserpass.org","CATEGORY","MyAwesomeSecurePassword",0,8,false,false,false,false)
if (Test0000 == "") {
    passedTests += 1
}

// 0001 - Symbols only
totalTests += 1
let Test0001 = await LPC.getPW("lesserpass.org","CATEGORY","MyAwesomeSecurePassword",0,8,false,false,false,true)
if (!Test0001.match(/[a-z]/)
    && !Test0001.match(/[A-Z]/)
    && !Test0001.match(/[0-9]/)
    && Test0001.match(/[^a-zA-Z0-9]/)) {
    passedTests += 1
}

// 0010 - Numbers only
totalTests += 1
let Test0010 = await LPC.getPW("lesserpass.org","CATEGORY","MyAwesomeSecurePassword",0,8,false,false,true,false)
if (!Test0010.match(/[a-z]/)
    && !Test0010.match(/[A-Z]/)
    && Test0010.match(/[0-9]/)
    && !Test0010.match(/[^a-zA-Z0-9]/)) {
    passedTests += 1
}

// 0011 - Numbers + Symbols
totalTests += 1
let Test0011 = await LPC.getPW("lesserpass.org","CATEGORY","MyAwesomeSecurePassword",0,8,false,false,true,true)
if (!Test0011.match(/[a-z]/)
    && !Test0011.match(/[A-Z]/)
    && Test0011.match(/[0-9]/)
    && Test0011.match(/[^a-zA-Z0-9]/)) {
    passedTests += 1
}

// 0100 - Caps only
totalTests += 1
let Test0100 = await LPC.getPW("lesserpass.org","CATEGORY","MyAwesomeSecurePassword",0,8,false,true,false,false)
if (!Test0100.match(/[a-z]/)
    && Test0100.match(/[A-Z]/)
    && !Test0100.match(/[0-9]/)
    && !Test0100.match(/[^a-zA-Z0-9]/)) {
    passedTests += 1
}

// 0101 - Caps + Symbols
totalTests += 1
let Test0101 = await LPC.getPW("lesserpass.org","CATEGORY","MyAwesomeSecurePassword",0,8,false,true,false,true)
if (!Test0101.match(/[a-z]/)
    && Test0101.match(/[A-Z]/)
    && !Test0101.match(/[0-9]/)
    && Test0101.match(/[^a-zA-Z0-9]/)) {
    passedTests += 1
}

// 0110 - Caps + Numbers

totalTests += 1
let Test0110 = await LPC.getPW("lesserpass.org","CATEGORY","MyAwesomeSecurePassword",0,8,false,true,true,false)
if (!Test0110.match(/[a-z]/)
    && Test0110.match(/[A-Z]/)
    && Test0110.match(/[0-9]/)
    && !Test0110.match(/[^a-zA-Z0-9]/)) {
    passedTests += 1
}

// 0111 - Caps + Numbers + Symbols

totalTests += 1
let Test0111 = await LPC.getPW("lesserpass.org","CATEGORY","MyAwesomeSecurePassword",0,8,false,true,true,true)
if (!Test0111.match(/[a-z]/)
    && Test0111.match(/[A-Z]/)
    && Test0111.match(/[0-9]/)
    && Test0111.match(/[^a-zA-Z0-9]/)) {
    passedTests += 1
}

// 1000 - Lowercase only
totalTests += 1
let Test1000 = await LPC.getPW("lesserpass.org","CATEGORY","MyAwesomeSecurePassword",0,8,true,false,false,false)
if (Test1000.match(/[a-z]/)
    && !Test1000.match(/[A-Z]/)
    && !Test1000.match(/[0-9]/)
    && !Test1000.match(/[^a-zA-Z0-9]/)) {
    passedTests += 1
}

// 1001 - Lowercase + Symbols
totalTests += 1
let Test1001 = await LPC.getPW("lesserpass.org","CATEGORY","MyAwesomeSecurePassword",0,8,true,false,false,true)
if (Test1001.match(/[a-z]/)
    && !Test1001.match(/[A-Z]/)
    && !Test1001.match(/[0-9]/)
    && Test1001.match(/[^a-zA-Z0-9]/)) {
    passedTests += 1
}

// 1010 - Lowercase + Numbers
totalTests += 1
let Test1010 = await LPC.getPW("lesserpass.org","CATEGORY","MyAwesomeSecurePassword",0,8,true,false,true,false)
if (Test1010.match(/[a-z]/)
    && !Test1010.match(/[A-Z]/)
    && Test1010.match(/[0-9]/)
    && !Test1010.match(/[^a-zA-Z0-9]/)) {
    passedTests += 1
}

// 1011 - Lowercase + Numbers + Symbols
totalTests += 1
let Test1011 = await LPC.getPW("lesserpass.org","CATEGORY","MyAwesomeSecurePassword",0,8,true,false,true,true)
if (Test1011.match(/[a-z]/)
    && !Test1011.match(/[A-Z]/)
    && Test1011.match(/[0-9]/)
    && Test1011.match(/[^a-zA-Z0-9]/)) {
    passedTests += 1
}

// 1100 - Lowercase + Caps
totalTests += 1
let Test1100 = await LPC.getPW("lesserpass.org","CATEGORY","MyAwesomeSecurePassword",0,8,true,true,false,false)
if (Test1100.match(/[a-z]/)
    && Test1100.match(/[A-Z]/)
    && !Test1100.match(/[0-9]/)
    && !Test1100.match(/[^a-zA-Z0-9]/)) {
    passedTests += 1
}

// 1101 - Lowercase + Caps + Symbols
totalTests += 1
let Test1101 = await LPC.getPW("lesserpass.org","CATEGORY","MyAwesomeSecurePassword",0,8,true,true,false,true)
if (Test1101.match(/[a-z]/)
    && Test1101.match(/[A-Z]/)
    && !Test1101.match(/[0-9]/)
    && Test1101.match(/[^a-zA-Z0-9]/)) {
    passedTests += 1
}

// 1110 - Lowercase + Caps + Numbers
totalTests += 1
let Test1110 = await LPC.getPW("lesserpass.org","CATEGORY","MyAwesomeSecurePassword",0,8,true,true,true,false)
if (Test1110.match(/[a-z]/)
    && Test1110.match(/[A-Z]/)
    && Test1110.match(/[0-9]/)
    && !Test1110.match(/[^a-zA-Z0-9]/)) {
    passedTests += 1
}

// 1111 - Lowercase + Caps + Numbers + Symbols
totalTests += 1
let Test1111 = await LPC.getPW("lesserpass.org","CATEGORY","MyAwesomeSecurePassword",0,8,true,true,true,true)
if (Test1111.match(/[a-z]/)
    && Test1111.match(/[A-Z]/)
    && Test1111.match(/[0-9]/)
    && Test1111.match(/[^a-zA-Z0-9]/)) {
    passedTests += 1
}

// Index test - different indexes should yield different outputs
totalTests += 1
let index0 = await LPC.getPW("lesserpass.org","INDEX","MyAwesomeSecurePassword",0,16,true,true,true,true)
let index1 = await LPC.getPW("lesserpass.org","INDEX","MyAwesomeSecurePassword",1,16,true,true,true,true)
let index2 = await LPC.getPW("lesserpass.org","INDEX","MyAwesomeSecurePassword",2,16,true,true,true,true)
let index3 = await LPC.getPW("lesserpass.org","INDEX","MyAwesomeSecurePassword",-1,16,true,true,true,true)
if (   index0 != index1
    && index0 != index2
    && index0 != index3

    && index1 != index2
    && index1 != index3

    && index2 != index3) {

    passedTests += 1
}

// Static secret test - different static secrets should yield different outputs
totalTests += 1
let LPC2 = new LPCore("AnotherStaticSecret","abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%&*?-_.+")
let staticSecret1 = await LPC.getPW("lesserpass.org","STATIC","MyAwesomeSecurePassword",0,16,true,true,true,true)
let staticSecret2 = await LPC2.getPW("lesserpass.org","STATIC","MyAwesomeSecurePassword",0,16,true,true,true,true)
if (staticSecret1 != staticSecret2) {
    passedTests += 1
}

// Charset test - different charsets should yield different outputs
totalTests += 1
let LPC3 = new LPCore("AnotherStaticSecret","aklmnopqrtuvwxzABCDEFGHIKLMNOPQRSTUVWXYZ01245689!@#$%*?-_+")
let charset1 = await LPC.getPW("lesserpass.org","CHARSET","MyAwesomeSecurePassword",0,16,true,true,true,true)
let charset2 = await LPC3.getPW("lesserpass.org","CHARSET","MyAwesomeSecurePassword",0,16,true,true,true,true)
if (charset1 != charset2) {
    passedTests += 1
}

// --- Below are tests for the passmoji stuff

// Same test as for PW generation - same inputs should yield same output across updates
totalTests += 1
let passmoji = await LPC.getPassMojis("MyAwesomeSecurePassword")
if (passmoji[0] == "🤛" &&
    passmoji[1] == "🐍" &&
    passmoji[2] == "🏆") {
    passedTests += 1
 }

// Different inputs should yield different outputs
totalTests += 1
let passmoji2 = await LPC.getPassMojis("MyAwesomeSecurePassword2")
if (passmoji != passmoji2) {
    passedTests += 1
 }

// ---

console.log(`Passed ${passedTests} / ${totalTests} tests. [${(passedTests/totalTests*100).toFixed(2)}%]`)
let testsPassedPercentage = (passedTests / totalTests) * 100;
if (testsPassedPercentage === 100) {
    console.log("All tests passed! 🎉")
    process.exit(0);
} else {
    console.log("Some tests failed. 😢")
    process.exit(1);
}
