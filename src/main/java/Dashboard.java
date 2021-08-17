import java.awt.Dimension;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.Scanner;

import javax.swing.Box;

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/**
 *
 * @author Jay
 */
class ItemView extends javax.swing.JPanel {

    private String itemId, itemName, itemPrice, itemImg, itemDuedate, itemOwner, username;
    private long daysBetween, difference_In_Time;
    static String ipath;
    static File itemData;
    Util obj;
    /**
     * Creates new form ItemView
     */
    public ItemView(String itemId, String itemName, String itemPrice, String itemImg, String itemDuedate, String username, String itemOwner) {
        this.itemId = itemId;
        this.itemName = itemName;
        this.itemPrice = itemPrice;
        this.itemImg = itemImg;
        this.itemDuedate = itemDuedate;
        this.username = username;
        this.itemOwner = itemOwner;
        ipath =  System.getProperty("user.dir") + File.separator + "AuctionSys Data" + File.separator + "ItemData.txt";
        itemData = new File(ipath);
        obj = new Util("item_access");
        checkDaysleft();
        initComponents();
        jLabel6.setVisible(false);
        jLabel7.setVisible(false);
        if(difference_In_Time == 0)
        {
            this.remove(jLabel2);
            this.remove(jTextField1);
            this.remove(jButton1);
            this.remove(jLabel6);
            jLabel7.setVisible(true);
        }
    }
    public void checkDaysleft()
    {
        SimpleDateFormat sdf = new SimpleDateFormat("dd-MM-yyyy");
		try
		{
			Date d1 = sdf.parse(sdf.format(new Date()));
			Date d2 = sdf.parse(itemDuedate);

			difference_In_Time = d2.getTime() - d1.getTime();

			daysBetween = (difference_In_Time / (1000 * 60 * 60 * 24)) % 365;
		}
		catch(ParseException e)
		{
			e.printStackTrace();
		}
    }
    private void replaceOldBid(String newValue)
    {
        try
        {    
            Scanner overwrt = new Scanner(itemData);
            StringBuffer buffer = new StringBuffer();

            while (overwrt.hasNextLine())
            {
                String temp = overwrt.nextLine();
                Scanner match = new Scanner(temp);
                match.useDelimiter("::");
                String id = match.next();
                if(id.equals(itemId))
                {
                    String tempName = username;
                    match.next();
                    buffer.append(id + "::" + tempName + "::" + obj.encrypt(newValue, id) + "::" + match.next() + "::" + match.next() + "::" + match.next() + System.lineSeparator());
                }
                else
                    buffer.append(id + "::" + match.next() + "::" + match.next() + "::" + match.next() + "::" + match.next() + "::" + match.next() + System.lineSeparator());
                match.close();
            }
            overwrt.close();

            String fileContents = buffer.toString();
            fileContents = fileContents.replaceFirst(obj.encrypt(itemPrice, itemId), newValue);
            FileWriter writer = new FileWriter(itemData);
            writer.append(fileContents);
            writer.flush();
            writer.close();
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
    // <editor-fold defaultstate="collapsed" desc="Generated Code">                          
    private void initComponents() {

        jLabel1 = new javax.swing.JLabel();
        jLabel2 = new javax.swing.JLabel();
        jLabel3 = new javax.swing.JLabel();
        jLabel4 = new javax.swing.JLabel();
        jButton1 = new javax.swing.JButton();
        jLabel5 = new javax.swing.JLabel();
        jTextField1 = new javax.swing.JTextField();
        jLabel6 = new javax.swing.JLabel();
        jLabel7 = new javax.swing.JLabel();

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
        jTextField1.setText("");
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
        jLabel6.setBounds(120, 140, 300, 30);

        jLabel7.setFont(new java.awt.Font("Segoe UI", 1, 18)); // NOI18N
        jLabel7.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
        jLabel7.setText("SOLD");
        jLabel7.setBorder(javax.swing.BorderFactory.createEtchedBorder());
        add(jLabel7);
        jLabel7.setBounds(200, 110, 80, 50);
    }// </editor-fold>                        
    private void jTextField1ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jTextField1ActionPerformed
        
    }//GEN-LAST:event_jTextField1ActionPerformed

    private void jButton1ActionPerformed(java.awt.event.ActionEvent evt) {                                         
        String temp = jTextField1.getText();
        if(temp.isBlank() || !obj.isNumeric(temp))
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
                {
                    replaceOldBid(temp);
                    jTextField1.setText("");
                }

            }
            else
            {
                jLabel6.setText("*Enter bid higher than current amount");
                jLabel6.setVisible(true);
            }
        }
    }                                        


    // Variables declaration - do not modify                     
    private javax.swing.JButton jButton1;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JLabel jLabel4;
    private javax.swing.JLabel jLabel5;
    private javax.swing.JLabel jLabel6;
    private javax.swing.JLabel jLabel7;
    private javax.swing.JTextField jTextField1;
    // End of variables declaration                   
}


public class Dashboard extends javax.swing.JFrame {

    String username, userID, name;
    private String itemId, itemName, itemPrice, itemImg, itemDuedate, itemOwner;
    Util obj = new Util("item_access");
    Scanner list;
    static ArrayList<String> oldItems;
    /**
     * Creates new form Dashboard
     */
    public Dashboard() {
        initComponents();
        jPanel1.setLayout(new javax.swing.BoxLayout(jPanel1, javax.swing.BoxLayout.Y_AXIS));
        jLabel4.setVisible(false);
        jLabel3.setVisible(false);
        try
        {
            listAllItems();
        }
        catch(IOException e)
        {
            System.out.println("ERROR : " + e);
        }
    }
    public void getData(String username, String userId, String name)
    {
        this.username = username;
        this.userID = userId;
        this.name = name;
        jLabel1.setText("Hi, " + name);
    }

    void listAllItems() throws IOException
    {
        jPanel1.removeAll();
        File itemData = new File(System.getProperty("user.dir") + File.separator + "AuctionSys Data" + File.separator + "ItemData.txt");
        if(itemData.exists() && itemData.length() > 0)
        {
            list = new Scanner(itemData);
            ArrayList<String> lines = new ArrayList<String>();
            oldItems = new ArrayList<String>();
            while (list.hasNextLine())
            {
                String temp = list.nextLine();
                if(!oldItems.contains(temp))
                    lines.add(temp);
            }
            list.close();
            
            for(String line : lines)
            {
                if(line.isBlank())
                    continue;
                Scanner match = new Scanner(line);
                match.useDelimiter("::");
                itemId = match.next();
                itemName = obj.decrypt(match.next(), itemId);
                itemPrice = obj.decrypt(match.next(), itemId);
                itemDuedate = obj.decrypt(match.next(), itemId);
                itemImg = match.next();
                itemOwner = match.next();
                match.close();

                ItemView newItem = new ItemView(itemId, itemName, itemPrice, itemImg, itemDuedate, username, itemOwner);
                jPanel1.add(Box.createRigidArea(new Dimension(10, 10)));
                newItem.setMaximumSize(new Dimension(Integer.MAX_VALUE, 180));
                newItem.setPreferredSize(new Dimension(480, 180));
                jPanel1.add(newItem);
                jPanel1.setVisible(true);

                oldItems.add(line);
            }
            lines.clear();
        }
    }
    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("@unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jLabel1 = new javax.swing.JLabel();
        jButton1 = new javax.swing.JButton();
        jButton2 = new javax.swing.JButton();
        jLabel2 = new javax.swing.JLabel();
        jButton3 = new javax.swing.JButton();
        jScrollPane1 = new javax.swing.JScrollPane();
        jPanel1 = new javax.swing.JPanel();
        jLabel3 = new javax.swing.JLabel();
        jLabel4 = new javax.swing.JLabel();

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);
        setBackground(new java.awt.Color(240, 241, 247));

        jLabel1.setFont(new java.awt.Font("Segoe UI", 1, 18)); // NOI18N
        jLabel1.setForeground(new java.awt.Color(34, 27, 64));

        jButton1.setIcon(new javax.swing.ImageIcon(getClass().getResource("/resources/user-logout-3056.jpg"))); // NOI18N
        jButton1.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseEntered(java.awt.event.MouseEvent evt) {
                jButton1MouseEntered(evt);
            }
            public void mouseExited(java.awt.event.MouseEvent evt) {
                jButton1MouseExited(evt);
            }
        });
        jButton1.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton1ActionPerformed(evt);
            }
        });

        jButton2.setIcon(new javax.swing.ImageIcon(getClass().getResource("/resources/plus-3107.jpg"))); // NOI18N
        jButton2.setPreferredSize(new java.awt.Dimension(60, 60));
        jButton2.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseEntered(java.awt.event.MouseEvent evt) {
                jButton2MouseEntered(evt);
            }
            public void mouseExited(java.awt.event.MouseEvent evt) {
                jButton2MouseExited(evt);
            }
        });
        jButton2.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton2ActionPerformed(evt);
            }
        });

        jLabel2.setFont(new java.awt.Font("Segoe UI", 1, 14)); // NOI18N
        jLabel2.setForeground(new java.awt.Color(244, 67, 54));
        jLabel2.setText("*Refresh after placing bid for updating changes");

        jButton3.setBackground(new java.awt.Color(35, 107, 195));
        jButton3.setFont(new java.awt.Font("Segoe UI", 1, 14)); // NOI18N
        jButton3.setForeground(new java.awt.Color(240, 241, 247));
        jButton3.setText("Refresh");
        jButton3.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton3ActionPerformed(evt);
            }
        });

        jScrollPane1.setHorizontalScrollBarPolicy(javax.swing.ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);

        jPanel1.setForeground(new java.awt.Color(240, 241, 247));
        jPanel1.setLayout(new javax.swing.BoxLayout(jPanel1, javax.swing.BoxLayout.LINE_AXIS));
        jScrollPane1.setViewportView(jPanel1);

        jLabel3.setFont(new java.awt.Font("Segoe UI", 1, 12)); // NOI18N
        jLabel3.setForeground(new java.awt.Color(34, 27, 64));
        jLabel3.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
        jLabel3.setText("Log out");

        jLabel4.setFont(new java.awt.Font("Segoe UI", 1, 12)); // NOI18N
        jLabel4.setForeground(new java.awt.Color(34, 27, 64));
        jLabel4.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
        jLabel4.setText("Add bid");

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGap(50, 50, 50)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jScrollPane1)
                    .addGroup(layout.createSequentialGroup()
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(layout.createSequentialGroup()
                                .addComponent(jLabel1, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                .addGap(80, 80, 80))
                            .addComponent(jLabel2, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                        .addGap(65, 65, 65)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                                .addComponent(jButton2, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addGap(18, 18, 18)
                                .addComponent(jButton1, javax.swing.GroupLayout.PREFERRED_SIZE, 60, javax.swing.GroupLayout.PREFERRED_SIZE))
                            .addComponent(jButton3, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.PREFERRED_SIZE, 138, javax.swing.GroupLayout.PREFERRED_SIZE)))
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                        .addGap(0, 0, Short.MAX_VALUE)
                        .addComponent(jLabel4, javax.swing.GroupLayout.PREFERRED_SIZE, 60, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(80, 80, 80)
                        .addComponent(jLabel3, javax.swing.GroupLayout.PREFERRED_SIZE, 60, javax.swing.GroupLayout.PREFERRED_SIZE)))
                .addGap(50, 50, 50))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel3)
                    .addComponent(jLabel4))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                    .addComponent(jButton2, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.PREFERRED_SIZE, 60, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jButton1, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.PREFERRED_SIZE, 60, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jLabel1, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jLabel2, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(jButton3, javax.swing.GroupLayout.PREFERRED_SIZE, 40, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(jScrollPane1, javax.swing.GroupLayout.DEFAULT_SIZE, 358, Short.MAX_VALUE)
                .addGap(30, 30, 30))
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private void jButton1ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton1ActionPerformed
        userID = "";
        username = "";
        name = "";
        this.dispose();
        LoginScreen login = new LoginScreen();
        login.setVisible(true);
    }//GEN-LAST:event_jButton1ActionPerformed

    private void jButton2ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton2ActionPerformed
        this.setVisible(false);
        AddBid newBid = new AddBid();
        newBid.setOldDash(this);
        newBid.setUsername(username);
        newBid.setVisible(true);
    }//GEN-LAST:event_jButton2ActionPerformed

    private void jButton3ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton3ActionPerformed
        try
        {
            listAllItems();
        }
        catch(IOException e)
        {
            System.out.println("ERROR : " + e);
        }
        jPanel1.revalidate();
        jPanel1.repaint();
    }//GEN-LAST:event_jButton3ActionPerformed

    private void jButton2MouseEntered(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_jButton2MouseEntered
        jLabel4.setVisible(true);
    }//GEN-LAST:event_jButton2MouseEntered

    private void jButton2MouseExited(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_jButton2MouseExited
        jLabel4.setVisible(false);
    }//GEN-LAST:event_jButton2MouseExited

    private void jButton1MouseEntered(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_jButton1MouseEntered
        jLabel3.setVisible(true);
    }//GEN-LAST:event_jButton1MouseEntered

    private void jButton1MouseExited(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_jButton1MouseExited
        jLabel3.setVisible(false);
    }//GEN-LAST:event_jButton1MouseExited

    /**
     * @param args the command line arguments
     */
    public static void main(String args[]) {
        /* Set the Nimbus look and feel */
        //<editor-fold defaultstate="collapsed" desc=" Look and feel setting code (optional) ">
        /* If Nimbus (introduced in Java SE 6) is not available, stay with the default look and feel.
         * For details see http://download.oracle.com/javase/tutorial/uiswing/lookandfeel/plaf.html 
         */
        try {
            for (javax.swing.UIManager.LookAndFeelInfo info : javax.swing.UIManager.getInstalledLookAndFeels()) {
                if ("Nimbus".equals(info.getName())) {
                    javax.swing.UIManager.setLookAndFeel(info.getClassName());
                    break;
                }
            }
        } catch (ClassNotFoundException ex) {
            java.util.logging.Logger.getLogger(Dashboard.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (InstantiationException ex) {
            java.util.logging.Logger.getLogger(Dashboard.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (IllegalAccessException ex) {
            java.util.logging.Logger.getLogger(Dashboard.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (javax.swing.UnsupportedLookAndFeelException ex) {
            java.util.logging.Logger.getLogger(Dashboard.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        }
        //</editor-fold>

        /* Create and display the form */
        java.awt.EventQueue.invokeLater(new Runnable() {
            public void run() {
                new Dashboard().setVisible(true);
            }
        });
    }

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton jButton1;
    private javax.swing.JButton jButton2;
    private javax.swing.JButton jButton3;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JLabel jLabel4;
    private javax.swing.JPanel jPanel1;
    private javax.swing.JScrollPane jScrollPane1;
    // End of variables declaration//GEN-END:variables
}
