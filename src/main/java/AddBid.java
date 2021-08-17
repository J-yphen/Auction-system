import java.awt.image.BufferedImage;
import java.io.File;
import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.Date;

import javax.imageio.ImageIO;
import javax.swing.JFileChooser;
import javax.swing.filechooser.FileNameExtensionFilter;

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/**
 *
 * @author Jay
 */
public class AddBid extends javax.swing.JFrame {

    private String name, price, dueDate, pathImg;
    private String userName;
    Util obj;
    Dashboard userdash;
    /**
     * Creates new form AddBid
     */
    public AddBid() {
        initComponents();
        this.setSize(630, 590);
        obj = new Util("item_access");
        jLabel7.setVisible(false);
        jLabel8.setVisible(false);
        jLabel6.setVisible(false);
        jDateChooser1.setDate(new Date());
    }

    public void setUsername(String uname)
    {
        userName = uname;
    }
    public void setOldDash(Dashboard userdash)
    {
        this.userdash = userdash;
    }
    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    // @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jFileChooser1 = new javax.swing.JFileChooser();
        jLabel1 = new javax.swing.JLabel();
        jLabel2 = new javax.swing.JLabel();
        jLabel3 = new javax.swing.JLabel();
        jLabel4 = new javax.swing.JLabel();
        jLabel5 = new javax.swing.JLabel();
        jTextField1 = new javax.swing.JTextField();
        jTextField2 = new javax.swing.JTextField();
        jTextField3 = new javax.swing.JTextField();
        jButton1 = new javax.swing.JButton();
        jButton2 = new javax.swing.JButton();
        jLabel6 = new javax.swing.JLabel();
        jLabel7 = new javax.swing.JLabel();
        jLabel8 = new javax.swing.JLabel();
        jDateChooser1 = new com.toedter.calendar.JDateChooser();
        jButton3 = new javax.swing.JButton();

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);
        setBackground(new java.awt.Color(240, 241, 247));
        getContentPane().setLayout(null);

        jLabel1.setBackground(new java.awt.Color(35, 107, 195));
        jLabel1.setFont(new java.awt.Font("Segoe UI", 1, 36)); // NOI18N
        jLabel1.setForeground(new java.awt.Color(240, 241, 247));
        jLabel1.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
        jLabel1.setText("ADD YOUR BID");
        jLabel1.setOpaque(true);
        getContentPane().add(jLabel1);
        jLabel1.setBounds(60, 40, 500, 70);

        jLabel2.setFont(new java.awt.Font("Segoe UI", 1, 14)); // NOI18N
        jLabel2.setForeground(new java.awt.Color(34, 27, 64));
        jLabel2.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
        jLabel2.setText("Set due Date");
        getContentPane().add(jLabel2);
        jLabel2.setBounds(100, 330, 150, 40);

        jLabel3.setFont(new java.awt.Font("Segoe UI", 1, 14)); // NOI18N
        jLabel3.setForeground(new java.awt.Color(34, 27, 64));
        jLabel3.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
        jLabel3.setText("Name of Bid");
        getContentPane().add(jLabel3);
        jLabel3.setBounds(100, 150, 150, 40);

        jLabel4.setFont(new java.awt.Font("Segoe UI", 1, 14)); // NOI18N
        jLabel4.setForeground(new java.awt.Color(34, 27, 64));
        jLabel4.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
        jLabel4.setText("Initial Price of Bid");
        getContentPane().add(jLabel4);
        jLabel4.setBounds(100, 210, 150, 40);

        jLabel5.setFont(new java.awt.Font("Segoe UI", 1, 14)); // NOI18N
        jLabel5.setForeground(new java.awt.Color(34, 27, 64));
        jLabel5.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
        jLabel5.setText("Path to image of Bid");
        getContentPane().add(jLabel5);
        jLabel5.setBounds(100, 270, 150, 40);

        jTextField1.setForeground(new java.awt.Color(34, 27, 64));
        jTextField1.setHorizontalAlignment(javax.swing.JTextField.CENTER);
        jTextField1.setText("Enter path of item image");
        getContentPane().add(jTextField1);
        jTextField1.setBounds(300, 270, 140, 40);

        jTextField2.setForeground(new java.awt.Color(34, 27, 64));
        jTextField2.setHorizontalAlignment(javax.swing.JTextField.CENTER);
        jTextField2.setText("Enter name of bid");
        jTextField2.addFocusListener(new java.awt.event.FocusAdapter() {
            public void focusLost(java.awt.event.FocusEvent evt) {
                jTextField2FocusLost(evt);
            }
        });
        getContentPane().add(jTextField2);
        jTextField2.setBounds(300, 150, 220, 40);

        jTextField3.setForeground(new java.awt.Color(34, 27, 64));
        jTextField3.setHorizontalAlignment(javax.swing.JTextField.CENTER);
        jTextField3.setText("Enter opening bid");
        jTextField3.addFocusListener(new java.awt.event.FocusAdapter() {
            public void focusLost(java.awt.event.FocusEvent evt) {
                jTextField3FocusLost(evt);
            }
        });
        jTextField3.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jTextField3ActionPerformed(evt);
            }
        });
        getContentPane().add(jTextField3);
        jTextField3.setBounds(300, 210, 220, 40);

        jButton1.setBackground(new java.awt.Color(244, 67, 54));
        jButton1.setFont(new java.awt.Font("Segoe UI", 1, 16)); // NOI18N
        jButton1.setForeground(new java.awt.Color(240, 241, 247));
        jButton1.setText("Cancel");
        jButton1.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton1ActionPerformed(evt);
            }
        });
        getContentPane().add(jButton1);
        jButton1.setBounds(340, 450, 190, 40);

        jButton2.setBackground(new java.awt.Color(64, 155, 115));
        jButton2.setFont(new java.awt.Font("Segoe UI", 1, 16)); // NOI18N
        jButton2.setForeground(new java.awt.Color(240, 241, 247));
        jButton2.setText("Submit");
        jButton2.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton2ActionPerformed(evt);
            }
        });
        getContentPane().add(jButton2);
        jButton2.setBounds(100, 450, 190, 40);

        jLabel6.setBackground(new java.awt.Color(240, 241, 247));
        jLabel6.setFont(new java.awt.Font("Segoe UI", 1, 14)); // NOI18N
        jLabel6.setForeground(new java.awt.Color(244, 67, 54));
        jLabel6.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
        getContentPane().add(jLabel6);
        jLabel6.setBounds(150, 390, 300, 40);

        jLabel7.setFont(new java.awt.Font("Segoe UI", 1, 14)); // NOI18N
        jLabel7.setForeground(new java.awt.Color(244, 67, 54));
        jLabel7.setText("*invalid");
        getContentPane().add(jLabel7);
        jLabel7.setBounds(530, 150, 60, 40);

        jLabel8.setFont(new java.awt.Font("Segoe UI", 1, 14)); // NOI18N
        jLabel8.setForeground(new java.awt.Color(244, 67, 54));
        jLabel8.setText("*invalid");
        getContentPane().add(jLabel8);
        jLabel8.setBounds(530, 210, 60, 40);

        jDateChooser1.setForeground(new java.awt.Color(34, 27, 64));
        jDateChooser1.addPropertyChangeListener(new java.beans.PropertyChangeListener() {
            public void propertyChange(java.beans.PropertyChangeEvent evt) {
                jDateChooser1PropertyChange(evt);
            }
        });
        getContentPane().add(jDateChooser1);
        jDateChooser1.setBounds(300, 330, 220, 40);

        jButton3.setBackground(new java.awt.Color(35, 107, 195));
        jButton3.setFont(new java.awt.Font("Segoe UI", 1, 12)); // NOI18N
        jButton3.setForeground(new java.awt.Color(240, 241, 247));
        jButton3.setText("Choose");
        jButton3.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton3ActionPerformed(evt);
            }
        });
        getContentPane().add(jButton3);
        jButton3.setBounds(450, 270, 70, 40);

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private void jTextField3ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jTextField3ActionPerformed
        
    }//GEN-LAST:event_jTextField3ActionPerformed

    private void jButton2ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton2ActionPerformed
        name = jTextField2.getText();
        price = jTextField3.getText();
        pathImg = jTextField1.getText();
        if(name.isBlank() || price.isBlank() || !obj.isNumeric(price))
        {
            if(name.isBlank())
                jLabel7.setVisible(true);
            else
                jLabel7.setVisible(false);
            
            if(!obj.isNumeric(price) || price.isBlank())
                jLabel8.setVisible(true);
            else
                jLabel8.setVisible(false);
        }
        else
        {
            File image = new File(pathImg);
            SimpleDateFormat sdf = new SimpleDateFormat("dd-MM-yyyy");
            dueDate = sdf.format(jDateChooser1.getDate());
            if(pathImg.isBlank())
            {
                jLabel6.setVisible(true);
                jLabel6.setText("Image path can not be empty");
            }
            else if(!image.exists())
            {
                jLabel6.setVisible(true);
                jLabel6.setText("Image path is invalid");
            }
            else
            {
                try
                {
                    if(obj.checkItem(obj.idGen(name)))
                    {
                        jLabel6.setVisible(true);
                        jLabel6.setText("Your bid name must be unique");
                    }
                    else
                    {
                        BufferedImage bimg = ImageIO.read(image);
                        int width = bimg.getWidth();
                        int height = bimg.getHeight();
                        if(width == 80 && height == 80)
                        {
                            jLabel6.setVisible(false);
                            obj.itemDataWrite(name, price, dueDate, pathImg, userName);
                            BidAddSuccess goDash = new BidAddSuccess();
                            userdash.setVisible(true);
                            goDash.setVisible(true);
                            this.dispose();
                        }
                        else
                        {
                            jLabel6.setVisible(true);
                            jLabel6.setText("Image dimention must be equal to 80 x 80");
                        }
                    }
                }
                catch(IOException e)
                {
                    System.out.println("ERROR : " + e);
                }
            }
        }
    }//GEN-LAST:event_jButton2ActionPerformed

    private void jDateChooser1PropertyChange(java.beans.PropertyChangeEvent evt) {//GEN-FIRST:event_jDateChooser1PropertyChange
        jDateChooser1.setMinSelectableDate(new Date());
    }//GEN-LAST:event_jDateChooser1PropertyChange

    private void jTextField2FocusLost(java.awt.event.FocusEvent evt) {//GEN-FIRST:event_jTextField2FocusLost
        name = jTextField2.getText();
        if(name.isBlank())
            jLabel7.setVisible(true);
        else
            jLabel7.setVisible(false);
    }//GEN-LAST:event_jTextField2FocusLost

    private void jTextField3FocusLost(java.awt.event.FocusEvent evt) {//GEN-FIRST:event_jTextField3FocusLost
        price = jTextField3.getText();

        if(!obj.isNumeric(price) || price.isBlank())
            jLabel8.setVisible(true);
        else
            jLabel8.setVisible(false);
    }//GEN-LAST:event_jTextField3FocusLost

    private void jButton3ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton3ActionPerformed
        // jDialog1.setVisible(true);
        jFileChooser1.setAcceptAllFileFilterUsed(false);
        jFileChooser1.setDialogTitle("select .jpg & .png only");

        FileNameExtensionFilter restrict = new FileNameExtensionFilter("JPG & PNG", "jpg", "png");
        jFileChooser1.addChoosableFileFilter(restrict);

        int r = jFileChooser1.showOpenDialog(null);

        if (r == JFileChooser.APPROVE_OPTION)
           jTextField1.setText(jFileChooser1.getSelectedFile().getAbsolutePath());
        else
           jTextField1.setText("Enter path of item image");
    }//GEN-LAST:event_jButton3ActionPerformed

    private void jButton1ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton1ActionPerformed
        Dashboard prev = new Dashboard();
        prev.setVisible(true);
        this.dispose();
    }//GEN-LAST:event_jButton1ActionPerformed

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
            java.util.logging.Logger.getLogger(AddBid.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (InstantiationException ex) {
            java.util.logging.Logger.getLogger(AddBid.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (IllegalAccessException ex) {
            java.util.logging.Logger.getLogger(AddBid.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (javax.swing.UnsupportedLookAndFeelException ex) {
            java.util.logging.Logger.getLogger(AddBid.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        }
        //</editor-fold>

        /* Create and display the form */
        java.awt.EventQueue.invokeLater(new Runnable() {
            public void run() {
                new AddBid().setVisible(true);
            }
        });
    }

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton jButton1;
    private javax.swing.JButton jButton2;
    private javax.swing.JButton jButton3;
    private com.toedter.calendar.JDateChooser jDateChooser1;
    private javax.swing.JFileChooser jFileChooser1;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JLabel jLabel4;
    private javax.swing.JLabel jLabel5;
    private javax.swing.JLabel jLabel6;
    private javax.swing.JLabel jLabel7;
    private javax.swing.JLabel jLabel8;
    private javax.swing.JTextField jTextField1;
    private javax.swing.JTextField jTextField2;
    private javax.swing.JTextField jTextField3;
    // End of variables declaration//GEN-END:variables
}