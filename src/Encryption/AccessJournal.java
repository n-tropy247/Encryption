/* 
 * Copyright (C) 2018 Ryan Castelli
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package Encryption;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.io.PrintWriter;
import java.io.File;

import java.time.LocalDateTime;

import java.time.format.DateTimeFormatter;

import java.util.ArrayList;
import java.util.Base64;
import java.util.Random;
import java.util.Scanner;

/**
 * A basic attempt at file encryption utilizing "AES" ciphers (proof of concept)
 *
 * @author: NTropy
 * @ver: 3/8/2018
 */
public class AccessJournal extends PersonalEncoder {

    private static int choice = 1;

    private static final ArrayList MESSAGE_LINES = new ArrayList();

    private static boolean boolDecrypted = false;

    private static final Scanner KB_READER = new Scanner(System.in);

    /**
     * Container for GUI, caller for other major methods
     *
     * @param args
     */
    public static void main(String args[]) {

        do {
            System.out.println("1) Show File Contents");
            System.out.println("2) Append to File");
            System.out.println("3) Encrypt File");
            System.out.println("0) Exit");

            System.out.print("\nYour choice?: ");

            choice = KB_READER.nextInt();

            switch (choice) {
                case 1:
                    showContents(); //see below
                    MESSAGE_LINES.clear(); //clears out old messages
                    break;

                case 2:
                    try { //necessary to catch IOException from writing/reading to/from a file
                        append(); //see below
                    } catch (Exception ex) {
                    }
                    MESSAGE_LINES.clear(); //clears out old messages
                    break;

                case 3:
                    try { //necessary to catch IOException from writing/reading to/from a file
                        encryptFile(); //see below
                    } catch (Exception ex) {
                    }
                    break;

                case 0:
                    choice = 0; //exits method and closes program instance
            }
        } while (choice != 0);
    }

    /**
     * Appends to end of Journal.txt
     *
     * @throws Exception
     */
    private static void append() throws Exception {
        if (!boolDecrypted) {
            decryptFile();
        }

        ArrayList copyLines = new ArrayList();

        if (MESSAGE_LINES.size() % 2 == 0) {
            for (int j = 0; j < MESSAGE_LINES.size() / 2; j++) {
                copyLines.add(MESSAGE_LINES.get(j));
            }
        } else {
            for (int j = 0; j < MESSAGE_LINES.size() / 2 + 1; j++) {
                copyLines.add(MESSAGE_LINES.get(j));
            }
        }
        System.out.print("\nPlease now add your journal entry, ending with \"enter\"");

        String addition = KB_READER.nextLine(); //takes entry as string

        LocalDateTime now = LocalDateTime.now(); //grabs time

        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"); //creates formatter for date and time

        String dateTime = now.format(formatter); //formats date and time

        String toBePrinted = ("[" + dateTime + "]" + " -- " + addition); //concatenates date and new entry

        copyLines.add(toBePrinted); //appends to new array

        try (PrintWriter printWithAdd = new PrintWriter("Journal.txt") //creates writer to print to journal file
                ) {
            for (int j = 0; j < copyLines.size(); j++) {
                printWithAdd.println(copyLines.get(j)); //adds each line from copyLines to file
            }
            printWithAdd.close();
        }

        MESSAGE_LINES.clear(); //clears out messages from MESSAGE_LINES after this temporary addition

        try { //necessary to catch IOException from writing/reading to/from a file
            encryptFile(); //re encrypts
        } catch (Exception ex) {
        }
    }

    /**
     * Shows contents of Journal.txt
     */
    private static void showContents() {
        if (!boolDecrypted) {
            try {
                decryptFile();
            } catch (Exception ex) {

            }
        }

        if (MESSAGE_LINES.size() % 2 == 0) //checks if even number of items in MESSAGE_LINES
        {
            for (int j = 0; j < MESSAGE_LINES.size() / 2; j++) {
                System.out.println(MESSAGE_LINES.get(j)); //print out each item
            }
        } else //if odd number of items in MESSAGE_LINES
        {
            for (int j = 0; j < MESSAGE_LINES.size() / 2 + 1; j++) {
                System.out.println(MESSAGE_LINES.get(j)); //print out each item
            }
        }
    }

    public static void decryptFile() throws Exception {

        Scanner keyInput;

        PrintWriter printToJournal;
        try (Scanner fileInput = new Scanner(new File("Journal.txt"))) {

            keyInput = new Scanner(new File("key.txt")); //reader for keyfile

            String temp;

            int recur = 1; //recursion marker for password entry

            ArrayList<String> textLines = new ArrayList(); //array of strings from decoded message

            SecretKey key = null; //instantiates SecretKey for use in decrypting. A SecretKey is a cryptographic algorithm. The same key/algorithm is used to encrypt/decrypt a file.

            while (keyInput.hasNext()) {
                textLines.add(keyInput.nextLine()); //adds everything in keyFile to an array (textLines)
            }
            String passCompare = textLines.get(0); //takes first line of new array

            byte[] IV = new byte[16]; //empty byte array for IvParameterSpec array

            while (recur == 1) { //loops until pass correctly entered
                System.out.print("\nEnter Pass: "); //asks for pass
                String passPlainText = KB_READER.nextLine(); //stores entry

                String passEncoded = encodePass(passPlainText); //encodes new pass using other class

                if (passCompare.length() - 1 == passEncoded.length()) //checks to make sure encrypting hasn't added hidden character (observed intermittent issue, temporary workaround)
                {
                    passCompare = passCompare.substring(0, passCompare.length());
                }

                if (passCompare.equals(passEncoded)) { //if hashes are equal then do below
                    recur = 0; //stop recursion of guessing

                    String keyToDecode = textLines.get(1); //gets key

                    byte[] decodedKey = Base64.getDecoder().decode(keyToDecode); //decodes key to byte array

                    key = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES"); //stores as key

                    for (int j = 0; j < 16; j++) {
                        IV[j] = Byte.valueOf(textLines.get(j + 2)); //grabs values for IvParameterSpec
                    }
                }
            }
            IvParameterSpec ivspec = new IvParameterSpec(IV); //creates IvParameterSpec from gathered values. An IvParameterSpec provides a pseudo previous block as an initialization vector for encryption/decryption

            Cipher decryptCipher = Cipher.getInstance("AES/CBC/PKCS5Padding"); //creates new AES cipher with PKCS5 padding (synonymous with PKCS7 in Java 8&9). A cipher is a cryptographic algorithm seeded with a key, a type of encryption, and a starting point

            decryptCipher.init(Cipher.DECRYPT_MODE, key, ivspec); //initiates cipher in decrypt mode using key and IvParameterSpec gathered from file

            byte[] decodeVal; //declares empty byte array to decode

            String decodeText; //declares empty string for final decoded line

            while (fileInput.hasNext()) { //while journal has more lines
                temp = fileInput.nextLine(); //sets temp string to next line (encoded)

                decodeVal = Base64.getDecoder().decode(temp.getBytes()); //uses Base64 to decode byte values

                decodeText = new String(decryptCipher.doFinal(decodeVal)); //decrypted with cipher and makes new string

                MESSAGE_LINES.add(decodeText); //adds to MESSAGE_LINES array
            }
            printToJournal = new PrintWriter("Journal.txt"); //prints decrypted stuff to file

            if (MESSAGE_LINES.size() % 2 == 0) {
                for (int j = 0; j < MESSAGE_LINES.size() / 2; j++) {
                    printToJournal.println(MESSAGE_LINES.get(j)); //print out each item
                }
            } else {
                for (int j = 0; j < MESSAGE_LINES.size() / 2 + 1; j++) {
                    printToJournal.println(MESSAGE_LINES.get(j)); //print out each item
                }
            }
            boolDecrypted = true;

            keyInput.close();
            printToJournal.close();
        }
    }

    /**
     * Uses AES ciphers to encrypt Journal.txt
     *
     * @throws Exception
     */
    private static void encryptFile() throws Exception {
        PrintWriter printToFile;
        PrintWriter printKey;
        try (Scanner fileInput = new Scanner(new File("Journal.txt"))) {

            Scanner keyInput = new Scanner(new File("key.txt")); //reader for key

            String temp; //empty string for encrypting

            ArrayList keyLines = new ArrayList(); //creates empty array list for lines from key file

            keyLines.add(keyInput.nextLine()); //grabs first line from key file (password)

            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES"); //creates AES key generator

            keyGenerator.init(128); //initiates generator with 128 bit encryption

            SecretKey key = keyGenerator.generateKey(); //generates new key. A SecretKey is a cryptographic algorithm. The same key/algorithm is used to encrypt/decrypt a file.

            keyLines.add(Base64.getEncoder().encodeToString(key.getEncoded())); //encodes key to String with Base64 and adds to keyLines array

            ArrayList textLines = new ArrayList(); //creteas empty array list for encrypted lines

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding"); //creates new AES cipher with PKCS5 padding (synonymous with PKCS7 in Java 8&9). A cipher is a cryptographic algorithm seeded with a key, a type of encryption, and a starting point

            Random rand = new Random(); //creates random number generator

            byte[] newRandom = new byte[16]; //new byte array with 16 indices

            for (int j = 0; j < 16; j++) {
                newRandom[j] = (byte) (rand.nextInt(127)); //randomly fills byte array (used to initialize IvParameterSpec)
            }
            IvParameterSpec ivspec = new IvParameterSpec(newRandom); //creates IvParameterSpec with byte array. An IvParameterSpec provides a pseudo previous block as an initialization vector for encryption/decryption

            cipher.init(Cipher.ENCRYPT_MODE, key, ivspec); //initiates cipher in encrypt mode using key and IvParameterSpec gathered from file

            byte[] cipherText; //array for initial text

            byte[] encodeVal; //array for encoded value

            while (fileInput.hasNext()) { //while journal has more lines
                temp = fileInput.nextLine(); //sets temp string to next line

                cipherText = cipher.doFinal(temp.getBytes()); //encrypts with cipher

                encodeVal = Base64.getEncoder().encode(cipherText); //encodes with Base64

                temp = new String(encodeVal); //creates new string from encodeVal

                textLines.add(temp); //adds to array of encoded lines
            }
            printToFile = new PrintWriter("Journal.txt"); //printer for journal

            printKey = new PrintWriter("key.txt"); //printer for key

            for (int j = 0; j < keyLines.size(); j++) {
                printKey.println(keyLines.get(j)); //adds all necessary lines to key file
            }
            for (int j = 0; j < textLines.size(); j++) {
                printToFile.println(textLines.get(j)); //adds all necessary lines to journal file
            }
            for (int j = 0; j < 16; j++) {
                printKey.println(newRandom[j]); //prints IvParameterSpec byte array to key file
            }
            boolDecrypted = false;
        }
        printToFile.close();
        printKey.close();
    }
}
