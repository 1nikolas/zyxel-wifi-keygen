#include <stdio.h>
#include <string.h>
#import <CommonCrypto/CommonDigest.h>

#define PTR_DAT_00077ee4 "agnahaakeaksalmaltalvandanearmaskaspattbagbakbiebilbitblablebliblyboabodbokbolbomborbrabrobrubudbuedaldamdegderdetdindisdraduedukdundypeggeieeikelgelvemueneengennertesseteettfeifemfilfinfloflyforfotfrafrifusfyrgengirglagregrogrygulhaihamhanhavheihelherhithivhoshovhuehukhunhushvaideildileinnionisejagjegjetjodjusjuvkaikamkankarkleklikloknaknekokkorkrokrykulkunkurladlaglamlavletlimlinlivlomloslovluelunlurlutlydlynlyrlysmaimalmatmedmegmelmenmermilminmotmurmyemykmyrnamnednesnoknyenysoboobsoddodeoppordormoseospossostovnpaiparpekpenpepperpippopradrakramrarrasremrenrevrikrimrirrisrivromroprorrosrovrursagsaksalsausegseiselsensessilsinsivsjusjyskiskoskysmisnesnusolsomsotspastistosumsussydsylsynsyvtaktaltamtautidtietiltjatogtomtretuetunturukeullulvungurourtutevarvedvegveivelvevvidvikvisvriyreyte"

struct mac {
    unsigned int mac_address;    // 4 bytes
    unsigned short mac_address2; // 2 bytes
};

union byte_str_u {
    struct {
        char byte_str[4];
        char byte_str4;
        char byte_str5;
        char byte_str6_63[58];
    };
    char byte_str_full[64];
};




void devCtl_getBaseMacAddress(struct mac *ret) {
    ret->mac_address = 0x04bf6ded;
    ret->mac_address2 = 0xc4f1;
}

void wlmngr_generateDefaultKey(int mode,int passphrase_length_param,char *passphrase)

{
    size_t str_length;
    int lookup_int;
    char char_temp;
    int passphrase_length;
    unsigned int sum;
    int j;
    int i;
    struct CC_MD5state_st MD5_context;
    unsigned char MAC_MD5_bytes [128];

    struct mac mac_address;

    union byte_str_u byte_str;

    char MAC_address_string [68];

    /* Init variables */
    sum = 0;
    memset(MAC_MD5_bytes,0,128);
    mac_address.mac_address = 0;
    mac_address.mac_address2 = 0;
    memset(byte_str.byte_str_full,0,64);
    memset(MAC_address_string,0,64);
    /*

       Depending on the mode, set the passphrase length */
    if (mode == 0) {
        passphrase_length = 26;
    }
    else if (mode == 1) {
        passphrase_length = 10;
    }
    else if (mode == 2) {
        passphrase_length = passphrase_length_param;
        if (passphrase_length_param == 0) {
            passphrase_length = 20;
        }
    }
    else if (mode == 3) {
        passphrase_length = 16;
    }
    else {
        passphrase_length = 10;
    }

    // Get the mac address bytes
    devCtl_getBaseMacAddress(&mac_address);
    /* Basically converting the mac address bytes into a string
       (for example 00B0D063C226) */
    sprintf(MAC_address_string,"%02x%02x%02x%02x%02x%02x",mac_address.mac_address >> 24,
            mac_address.mac_address >> 16 & 0xff,mac_address.mac_address >> 8 & 0xff,mac_address.mac_address & 0xff,
            (unsigned int)((mac_address.mac_address2 >> 8) & 0xFF), (unsigned int)mac_address.mac_address2 & 0xff);


    // Calculates an MD5 hash
    // Uses the BSD MD5 library
    //memset(MD5_context,0,88);
    memset(MAC_MD5_bytes,0,128);
    memset(passphrase,0,4);
    /* Initialize the MD5 context */
    CC_MD5_Init(&MD5_context);
    /* Length is always 12 */
    str_length = strlen(MAC_address_string);
    /* Set the string to compute the hash and its length */
    CC_MD5_Update(&MD5_context,MAC_address_string,str_length);
    /* Finally get the MD5 bytes */
    CC_MD5_Final(MAC_MD5_bytes, &MD5_context);
    /*


       For each byte of the MD5 */
    for (i = 0; i < 16; i = i + 1) {
        /* Reset the byte_str variable */
        memset(byte_str.byte_str_full,0,64);
        /* Put in byte_str the hex representation of the bytes
           Because we are converting a byte into hex the minimum value is 0 and the
           maximum is ff so it can be either 1 or 2 character long */
        sprintf(byte_str.byte_str_full,"%x",(unsigned int)MAC_MD5_bytes[i]);
        /* Check if each character is a lowercase letter and convert it to uppercase */
        if (('`' < byte_str.byte_str_full[0]) && (byte_str.byte_str_full[0] < '{')) {
            byte_str.byte_str_full[0] = byte_str.byte_str_full[0] + -32;
        }
        if (('`' < byte_str.byte_str_full[1]) && (byte_str.byte_str_full[1] < '{')) {
            byte_str.byte_str_full[1] = byte_str.byte_str_full[1] + -32;
        }
        /* If the byte_str is 1 character long, put in the second character the same
           value that the first one has */
        str_length = strlen(byte_str.byte_str_full);
        if (str_length == 1) {
            byte_str.byte_str_full[1] = byte_str.byte_str_full[0];
        }

        /* If it's the first loop, reset the passphrase output string and write whatever
           the byte_str has, otherwise append it */
        if (i < 1) {
            *passphrase = '\0';
            strcpy(passphrase,byte_str.byte_str_full);
        }
        else {
            strcat(passphrase,byte_str.byte_str_full);
        }
        /* Keep the sum of all the character ascii codes in all loops */
        sum = sum + (int)byte_str.byte_str_full[0] + (int)byte_str.byte_str_full[1];
    }

    /*

       Reset byte_str and MAC_MD5_bytes */
    byte_str.byte_str_full[0] = '\0';
    MAC_MD5_bytes[0] = 0;
    /* Backup what we constructed into byte_str */
    strcpy(byte_str.byte_str_full,passphrase);
    /*


       Now it converts the sum into a 0-264 integer and looks in an 795 character
       long string (character table) the 3 continious characters which are on the
       integer*3, +1 and +2 of the lookup table (265*3 is 795 so it looks on the
       whole character table*). Then it gets the hex values of the ascii code of
       each character) into MAC_MD5_bytes.

       * BUG! if (sum % 265) is 264, it will look outside the string
       (char_table[265] is \0 and char_table[266] is outside that string) */
    lookup_int = (int)sum % 265;
    sprintf((char *)MAC_MD5_bytes,"%x%x%x",(unsigned int)(char)PTR_DAT_00077ee4[lookup_int * 3],
            (unsigned int)(char)PTR_DAT_00077ee4[lookup_int * 3 + 1],
            (unsigned int)(char)PTR_DAT_00077ee4[lookup_int * 3 + 2]);

    /*

       Checks if the sum is even */
    if ((sum & 1) == 0) {
        /* For each of the 6 characters (3 characters coonverted to ascii ints and then
           printed as hex, ascii lowercase letters in hex are 66-7a, so 6 characters) */
        for (i = 0; i < 6; i = i + 1) {
            /* If that character is not a lowercase letter do nothing
               Otherwise convert it to uppercase and set it back */
            if ((MAC_MD5_bytes[i] < 97) || (122 < MAC_MD5_bytes[i])) {
                char_temp = MAC_MD5_bytes[i];
            }
            else {
                char_temp = MAC_MD5_bytes[i] - 32;
            }
            MAC_MD5_bytes[i] = char_temp;
        }
    }
    /*

       Now we assemble everything into a string (MAC_address_string)

       - byte_str now has the md5 of the mac address custom-converted into a string
       (32 bytes/characters long)
       - MAC_MD5_bytes has the hex of the ascii of the 3 characters from the
       character table (6 bytes/characters long) */
    sprintf(MAC_address_string,"%c%c%c%c%c%c%c%c%c%c%c%c%s",(int)byte_str.byte_str[0],(unsigned int)MAC_MD5_bytes[0],
            (unsigned int)MAC_MD5_bytes[1],(int)byte_str.byte_str[1],(int)byte_str.byte_str[2],(unsigned int)MAC_MD5_bytes[2],
            (unsigned int)MAC_MD5_bytes[3],(int)byte_str.byte_str[3],(int)byte_str.byte_str4,(int)byte_str.byte_str5,
            (unsigned int)MAC_MD5_bytes[4],(unsigned int)MAC_MD5_bytes[5],byte_str.byte_str6_63);

    /*

       MD5 Again!
       Reset the md5 variables */
    //memset(MD5_context,0,88);
    memset(MAC_MD5_bytes,0,128);
    memset(passphrase,0,4);
    /* Init context */
    CC_MD5_Init(&MD5_context);
    str_length = strlen(MAC_address_string);
    /* Set string to hash the MAC_address_string (the assembled string) */
    CC_MD5_Update(&MD5_context,MAC_address_string,str_length);
    /* Get the MD5 bytes into MAC_MD5_bytes */
    CC_MD5_Final(MAC_MD5_bytes, &MD5_context);
    /*

       Do the same conversion to string as previously */
    for (i = 0; i < 16; i = i + 1) {
        memset(byte_str.byte_str_full,0,64);
        sprintf(byte_str.byte_str_full,"%x",(unsigned int)MAC_MD5_bytes[i]);
        if (('`' < byte_str.byte_str_full[0]) && (byte_str.byte_str_full[0] < '{')) {
            byte_str.byte_str_full[0] = byte_str.byte_str_full[0] + -32;
        }
        if (('`' < byte_str.byte_str_full[1]) && (byte_str.byte_str_full[1] < '{')) {
            byte_str.byte_str_full[1] = byte_str.byte_str_full[1] + -32;
        }
        str_length = strlen(byte_str.byte_str_full);
        if (str_length == 1) {
            byte_str.byte_str_full[1] = byte_str.byte_str_full[0];
        }
        if (i < 1) {
            *passphrase = '\0';
            strcpy(passphrase,byte_str.byte_str_full);
        }
        else {
            strcat(passphrase,byte_str.byte_str_full);
        }
    }
    passphrase[40] = '\0';
    printf("%s\n", passphrase);
    /*

       If n is the length we calculated in the beginning

       Mode 0 -> we keep the first n characters
       Mode 1 -> we keep the last 10 characters reversed
       Mode 2 -> we keep from (26-n)th to 26th character
       Mode 3 -> we keep from the 2nd to the 17th character reversed
       Otherwise -> we keep the last 10 characters reversed */
    if (mode == 0) {
        passphrase[passphrase_length] = '\0';
    }
    else if (mode == 1) {
        strcpy(byte_str.byte_str_full,passphrase);
        *passphrase = '\0';
        i = 31;
        for (j = 0; j < 10; j = j + 1) {
            passphrase[j] = byte_str.byte_str_full[i];
            i = i + -1;
        }
        passphrase[j] = '\0';
    }
    else if (mode == 2) {
        strcpy(byte_str.byte_str_full,passphrase);
        *passphrase = '\0';
        i = 25;
        j = passphrase_length;
        while (j = j + -1, -1 < j) {
            passphrase[j] = byte_str.byte_str_full[i];
            i = i + -1;
        }
        passphrase[passphrase_length] = '\0';
    }
    else if (mode == 3) {
        strcpy(byte_str.byte_str_full,passphrase);
        *passphrase = '\0';
        i = 16;
        for (j = 0; j < 16; j = j + 1) {
            passphrase[j] = byte_str.byte_str_full[i];
            i = i + -1;
        }
        passphrase[j] = '\0';
    }
    else {
        strcpy(byte_str.byte_str_full,passphrase);
        *passphrase = '\0';
        i = 31;
        for (j = 0; j < 10; j = j + 1) {
            passphrase[j] = byte_str.byte_str_full[i];
            i = i + -1;
        }
        passphrase[j] = '\0';
    }

    return;
}


int main() {
    char out[64];

    wlmngr_generateDefaultKey(2, 20, out);
    printf("%s\n", out);


    return 0;
}