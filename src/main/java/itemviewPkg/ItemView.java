package itemviewPkg;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.security.MessageDigest;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.Scanner;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/**
 *
 * @author Jay
 */
public class ItemView extends javax.swing.JPanel {

    private static String itemId, itemName, itemPrice, itemImg, itemDuedate, itemOwner, username;
    private static long daysBetween;
    static String ipath;
    static File itemData;
    /**
     * Creates new form ItemView
     */
    public ItemView(String itemId, String itemName, String itemPrice, String itemImg, String itemDuedate, String username, String itemOwner) {
        initComponents();
        ItemView.itemId = itemId;
        ItemView.itemName = itemName;
        ItemView.itemPrice = itemPrice;
        ItemView.itemImg = itemImg;
        ItemView.itemDuedate = itemDuedate;
        ItemView.username = username;
        ItemView.itemOwner = itemOwner;
        jLabel6.setVisible(false);
        ipath =  System.getProperty("user.dir") + File.separator + "AuctionSys Data" + File.separator + "ItemData.txt";
        itemData = new File(ipath);
    }
    public void checkDaysleft()
    {
        SimpleDateFormat sdf = new SimpleDateFormat("dd-MM-yyyy");
		try
		{
			Date d1 = sdf.parse(sdf.format(new Date()));
			Date d2 = sdf.parse(itemDuedate);

			long difference_In_Time = d2.getTime() - d1.getTime();

			daysBetween = (difference_In_Time / (1000 * 60 * 60 * 24)) % 365;
		}
		catch(ParseException e)
		{
			e.printStackTrace();
		}
    }
    private void replaceOldBid(String newValue)
    {
        newValue = encrypt(newValue, itemId);
        try
        {    
            Scanner overwrt = new Scanner(itemData);
            StringBuffer buffer = new StringBuffer();

            while (overwrt.hasNextLine())
                buffer.append(overwrt.nextLine() + System.lineSeparator());
            
            String fileContents = buffer.toString();
            overwrt.close();
            fileContents = fileContents.replaceFirst(itemPrice, newValue);
            FileWriter writer = new FileWriter(itemData);
            writer.append(fileContents);
            writer.flush();
            writer.close();
            // while(overwrt.hasNextLine())
            // {
            //     String match = overwrt.nextLine();
            //     if(match.contains(itemPrice))
            //     {
            //         // match.replaceFirst(itemPrice, newValue);
            //         // Scanner replace = new Scanner(match);
            //         // replace.nextLine();
            //         // replace.nextLine();
            //         // replace.
            //         // replace.close();
            //     }
            // }
            overwrt.close();
        }
        catch(FileNotFoundException e)
        {
            System.out.println("ERROR : " + e);
        }
        catch(IOException e)
        {
            System.out.println("ERROR : " + e);
        }
    }
    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    // @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jLabel1 = new javax.swing.JLabel();
        jLabel2 = new javax.swing.JLabel();
        jLabel3 = new javax.swing.JLabel();
        jLabel4 = new javax.swing.JLabel();
        jButton1 = new javax.swing.JButton();
        jLabel5 = new javax.swing.JLabel();
        jTextField1 = new javax.swing.JTextField();
        jLabel6 = new javax.swing.JLabel();

        setBorder(javax.swing.BorderFactory.createBevelBorder(javax.swing.border.BevelBorder.RAISED));
        setEnabled(false);
        setMinimumSize(new java.awt.Dimension(480, 180));
        setLayout(null);

        jLabel1.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
        jLabel1.setIcon(new javax.swing.ImageIcon(itemImg)); // NOI18N
        jLabel1.setBorder(javax.swing.BorderFactory.createBevelBorder(javax.swing.border.BevelBorder.RAISED));
        add(jLabel1);
        jLabel1.setBounds(10, 10, 80, 80);

        jLabel2.setFont(new java.awt.Font("Segoe UI", 1, 14)); // NOI18N
        jLabel2.setText("Set bid : ");
        add(jLabel2);
        jLabel2.setBounds(110, 90, 60, 40);

        jLabel3.setFont(new java.awt.Font("Segoe UI", 1, 14)); // NOI18N
        jLabel3.setText("Name of product : " + itemName);
        add(jLabel3);
        jLabel3.setBounds(110, 10, 360, 30);

        jLabel4.setFont(new java.awt.Font("Segoe UI", 1, 14)); // NOI18N
        jLabel4.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
        jLabel4.setText(daysBetween + " days left");
        add(jLabel4);
        jLabel4.setBounds(10, 90, 80, 40);

        jButton1.setText("Place bid");
        jButton1.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton1ActionPerformed(evt);
            }
        });
        add(jButton1);
        jButton1.setBounds(390, 90, 80, 40);

        jLabel5.setFont(new java.awt.Font("Segoe UI", 1, 14)); // NOI18N
        jLabel5.setText("Highest bid of item : Rs. " + itemPrice);
        add(jLabel5);
        jLabel5.setBounds(110, 50, 360, 30);

        jTextField1.setHorizontalAlignment(javax.swing.JTextField.CENTER);
        jTextField1.setText("Enter amount higer than current bid");
        jTextField1.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jTextField1ActionPerformed(evt);
            }
        });
        add(jTextField1);
        jTextField1.setBounds(170, 90, 205, 40);

        jLabel6.setFont(new java.awt.Font("Segoe UI", 1, 14)); // NOI18N
        jLabel6.setForeground(new java.awt.Color(255, 0, 0));
        jLabel6.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
        jLabel6.setText("*Enter bid higher than current amount");
        add(jLabel6);
        jLabel6.setBounds(120, 140, 260, 30);
    }// </editor-fold>//GEN-END:initComponents

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
    private void jTextField1ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jTextField1ActionPerformed
        
    }//GEN-LAST:event_jTextField1ActionPerformed

    private void jButton1ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton1ActionPerformed
        String temp = jTextField1.getText();
        if(temp.isBlank() || !isNumeric(temp))
        {
            jLabel6.setText("*Field must be a numeric value");
            jLabel6.setVisible(true);
        }
        else
        {
            if(Long.parseLong(temp) > Long.parseLong(itemPrice))
            {
                if(itemOwner.equals(username))
                {
                    jLabel6.setText("*You own this bid, you cannot bid on this");
                    jLabel6.setVisible(true);
                }
                else
                    replaceOldBid(temp);
            }
            else
            {
                jLabel6.setText("*Enter bid higher than current amount");
                jLabel6.setVisible(true);
            }
        }
    }//GEN-LAST:event_jButton1ActionPerformed


    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton jButton1;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JLabel jLabel4;
    private javax.swing.JLabel jLabel5;
    private javax.swing.JLabel jLabel6;
    private javax.swing.JTextField jTextField1;
    // End of variables declaration//GEN-END:variables
}