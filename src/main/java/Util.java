import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Base64;
import java.util.Scanner;
import java.util.UUID;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

class Util
{
    String path, ipath;
    File file, itemData;
    private String userId, name, phoneNo ,username, password;
    private String iname, iprice, Duedate, itemId, imgpath, accessUname;
    public Util(String mode)
    {
        try
        {
            if(mode.equals("login"))
            {
                path =  System.getProperty("user.dir") + File.separator + "AuctionSys Data" + File.separator + "User.txt";
                file = new File(path);
                file.getParentFile().mkdirs();
                file.createNewFile();
            }
            else
            {
                ipath =  System.getProperty("user.dir") + File.separator + "AuctionSys Data" + File.separator + "ItemData.txt";
                itemData = new File(ipath);
                itemData.createNewFile();
            }
        }
        catch(IOException e)
        {
            System.out.println("ERROR : "+ e);
        }
    }
    public String getUID()
    {
        return userId;
    }
    public String getName()
    {
        return name;
    }
    public String getPhone()
    {
        return phoneNo;
    }
    public boolean isNumeric(String str)
    { 
        try
        {  
            Double.parseDouble(str);  
            return true;
        }
        catch(NumberFormatException e)
        {  
            return false;  
        }  
    }
    public void store_to_file(String name, String phoneNo, String username, String password) throws IOException
    {
        userId = idGen(username);
        password = encrypt(password, userId);
        phoneNo = encrypt(phoneNo, userId);
        name = encrypt(name, userId);

        FileWriter writer = new FileWriter(file, true);
        PrintWriter out = new PrintWriter(writer);
        out.println(userId +"::"+ name +"::"+ phoneNo +"::"+ username +"::"+ password);
        writer.close();
    }
    public boolean matchPass(String pass) throws IOException
    {
        pass = encrypt(pass, userId);
        return matchText(pass, "pass");
    }
    public boolean matchText(String id, String type) throws IOException 
    {
        final Scanner scanner = new Scanner(file);                     //type = "uname" for usrname match & type = "pass" for password match
        while (scanner.hasNextLine())
        {
            final String lineFromFile = scanner.nextLine();
            Scanner match = new Scanner(lineFromFile);
            match.useDelimiter("::");
            userId = match.next();
            name = match.next();
            phoneNo = match.next();
            username = match.next();
            password = match.next();
            match.close();
            if(type.equals("uname") && username.equals(id))
                return true;
            if(type.equals("pass") && password.equals(id))
                return true;
        }
        scanner.close();
        return false;
    }
    public String getImgpath()
    {
        return imgpath;
    }
    public void itemDataWrite(String iname, String iprice, String Duedate, String imgpath, String accessUname)
    {
        itemId = idGen(iname);
        this.iname = encrypt(iname, itemId);
        this.iprice = encrypt(iprice, itemId);
        this.Duedate = encrypt(Duedate, itemId);
        this.imgpath = imgpath;
        this.accessUname = accessUname;
        try
        {
            FileWriter writer = new FileWriter(itemData, true);
            PrintWriter out = new PrintWriter(writer);
            out.println(itemId +"::"+ this.iname +"::"+ this.iprice +"::"+ this.Duedate +"::"+ imgpath +"::"+ accessUname);
            writer.close();
        }
        catch(IOException e)
        {
            System.out.println("ERROR : " + e);
        }
    }
    public boolean checkItem(String id) throws IOException 
    {
        final Scanner scanner = new Scanner(itemData);
        while (scanner.hasNextLine())
        {
            final String lineFromFile = scanner.nextLine();
            Scanner match = new Scanner(lineFromFile);
            match.useDelimiter("::");
            itemId = match.next();
            iname = match.next();
            iprice = match.next();
            Duedate = match.next();
            imgpath = match.next();
            accessUname = match.next();
            match.close();
            if(itemId.equals(id))
                return true;
            if(accessUname.equals(itemId))
                return true;
        }
        scanner.close();
        return false;
    }
    public String idGen(String username)
    {
        String userid = UUID.nameUUIDFromBytes(username.getBytes()).toString();
        return userid;
    }
    public String sha128(String in)
    {
        MessageDigest sha;
        byte[] digest;
        try
        {
            sha = MessageDigest.getInstance("SHA-1");
            digest = sha.digest(in.getBytes("UTF-16"));
        }
        catch(Exception e)
        {
            e.printStackTrace();
            return null;
        }
        String encoded = Base64.getEncoder().encodeToString(digest);
        return encoded;
    }
    public String encrypt(String strToEncrypt, String secret)
    {
        try
        {
            SecretKeySpec secretKey = new SecretKeySpec(Arrays.copyOf(sha128(secret).getBytes(), 16), "AES");
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            return Base64.getEncoder().encodeToString(cipher.doFinal(strToEncrypt.getBytes()));
        }
        catch (Exception e)
        {
            System.out.println("Error while encrypting: " + e.toString());
        }
        return null;
    }
    public String decrypt(String strToDecrypt, String secret)
    {
        try
        {
            SecretKeySpec secretKey = new SecretKeySpec(Arrays.copyOf(sha128(secret).getBytes(), 16), "AES");
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5PADDING");
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            return new String(cipher.doFinal(Base64.getDecoder().decode(strToDecrypt)));
        }
        catch (Exception e)
        {
            System.out.println("Error while decrypting: " + e.toString());
        }
        return null;
    }
}
