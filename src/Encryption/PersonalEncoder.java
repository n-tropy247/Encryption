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

import java.io.FileNotFoundException;
import java.io.PrintWriter;

import java.util.Scanner;

/**
 * Basic encoder for passwords
 *
 * @author NTropy
 * @version 4/17/2018
 */
public class PersonalEncoder {

    /**
     * Constructor
     */
    public PersonalEncoder() {
    }

    /**
     * Encodes password by shifting characters, not secure!
     * @param origPass
     * @return encoded password
     */
    public static String encodePass(String origPass) {
        char[] passArray = origPass.toCharArray();

        for (int j = 0; j < passArray.length; j++) 
        {
            passArray[j] = (char) (((int) passArray[j]) - 40);
        }

        for (int j = passArray.length - 1; j > 0; j--)
        {
            passArray[j] = (char) (((int) passArray[passArray.length - j]) - 1);
        }

        return (new String(passArray));
    }

    /**
     * Writes first-time password entered via console to key file
     */
    private static void writePass() {
        try (PrintWriter writeToFile = new PrintWriter("key.txt")) {
            Scanner kbReader = new Scanner(System.in);
            
            String pass;
            String pass2;
            do {
                System.out.print("\nEnter Pass: ");
                pass = kbReader.nextLine();
                System.out.println("\nEnter Again: ");
                pass2 = kbReader.nextLine();
            } while (!pass.equals(pass2));
            String encoded = encodePass(pass); 
            writeToFile.println(encoded);
            writeToFile.close();
        } catch (FileNotFoundException e) {
        }
    }

    /**
     * Asks for key and shows encoded value in console.
     * For debugging use
     */
    private static void printKey() {
        Scanner kbReader = new Scanner(System.in);

        String pass;
        String pass2;

        do {
            System.out.print("\nEnter Pass: ");
            pass = kbReader.nextLine();
            System.out.println("\nEnter Again: ");
            pass2 = kbReader.nextLine();
        } while (!pass.equals(pass2));
        String encoded = encodePass(pass);

        System.out.println(encoded);
    }
}
