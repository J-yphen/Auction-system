import java.io.IOException;
/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/**
 *
 * @author Jay
 */
public class SignupScreen extends javax.swing.JFrame {

    private String name, phn, uname, pass, rpass;
    private Util obj = new Util("login");
    /**
     * Creates new form SignupScreen
     */
    public SignupScreen() {
        initComponents();
        this.setSize(600, 643);
        jLabel9.setVisible(false);
        jLabel11.setVisible(false);
        jLabel12.setVisible(false);
        jLabel10.setVisible(false);
    }

    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    // @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jLabel2 = new javax.swing.JLabel();
        jLabel1 = new javax.swing.JLabel();
        jLabel3 = new javax.swing.JLabel();
        jLabel4 = new javax.swing.JLabel();
        jLabel5 = new javax.swing.JLabel();
        jLabel6 = new javax.swing.JLabel();
        jButton1 = new javax.swing.JButton();
        jButton2 = new javax.swing.JButton();
        jTextField2 = new javax.swing.JTextField();
        jTextField4 = new javax.swing.JTextField();
        jTextField3 = new javax.swing.JTextField();
        jPasswordField1 = new javax.swing.JPasswordField();
        jPasswordField2 = new javax.swing.JPasswordField();
        jLabel9 = new javax.swing.JLabel();
        jLabel10 = new javax.swing.JLabel();
        jLabel11 = new javax.swing.JLabel();
        jLabel12 = new javax.swing.JLabel();
        jLabel7 = new javax.swing.JLabel();

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);
        getContentPane().setLayout(null);

        jLabel2.setBackground(new java.awt.Color(102, 0, 102));
        jLabel2.setFont(new java.awt.Font("Segoe UI Black", 1, 36)); // NOI18N
        jLabel2.setForeground(new java.awt.Color(240, 241, 247));
        jLabel2.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
        jLabel2.setText("SIGN UP");
        jLabel2.setBorder(new javax.swing.border.SoftBevelBorder(javax.swing.border.BevelBorder.RAISED, null, java.awt.Color.white, java.awt.Color.white, null));
        jLabel2.setOpaque(true);
        getContentPane().add(jLabel2);
        jLabel2.setBounds(90, 10, 400, 70);

        jLabel1.setBackground(new java.awt.Color(77, 34, 89));
        jLabel1.setFont(new java.awt.Font("Segoe UI", 1, 14)); // NOI18N
        jLabel1.setForeground(new java.awt.Color(240, 241, 247));
        jLabel1.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
        jLabel1.setText("Re-enter Password");
        jLabel1.setOpaque(true);
        getContentPane().add(jLabel1);
        jLabel1.setBounds(90, 370, 140, 40);
        jLabel1.getAccessibleContext().setAccessibleName("Username");

        jLabel3.setBackground(new java.awt.Color(77, 34, 89));
        jLabel3.setFont(new java.awt.Font("Segoe UI", 1, 14)); // NOI18N
        jLabel3.setForeground(new java.awt.Color(240, 241, 247));
        jLabel3.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
        jLabel3.setText("Name");
        jLabel3.setOpaque(true);
        getContentPane().add(jLabel3);
        jLabel3.setBounds(90, 130, 140, 40);

        jLabel4.setBackground(new java.awt.Color(77, 34, 89));
        jLabel4.setFont(new java.awt.Font("Segoe UI", 1, 14)); // NOI18N
        jLabel4.setForeground(new java.awt.Color(240, 241, 247));
        jLabel4.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
        jLabel4.setText("Phone No.");
        jLabel4.setOpaque(true);
        getContentPane().add(jLabel4);
        jLabel4.setBounds(90, 190, 140, 40);

        jLabel5.setBackground(new java.awt.Color(77, 34, 89));
        jLabel5.setFont(new java.awt.Font("Segoe UI", 1, 14)); // NOI18N
        jLabel5.setForeground(new java.awt.Color(240, 241, 247));
        jLabel5.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
        jLabel5.setText("Username");
        jLabel5.setOpaque(true);
        getContentPane().add(jLabel5);
        jLabel5.setBounds(90, 250, 140, 40);

        jLabel6.setBackground(new java.awt.Color(77, 34, 89));
        jLabel6.setFont(new java.awt.Font("Segoe UI", 1, 14)); // NOI18N
        jLabel6.setForeground(new java.awt.Color(240, 241, 247));
        jLabel6.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
        jLabel6.setText("Password");
        jLabel6.setOpaque(true);
        getContentPane().add(jLabel6);
        jLabel6.setBounds(90, 310, 140, 40);

        jButton1.setBackground(new java.awt.Color(77, 34, 89));
        jButton1.setFont(new java.awt.Font("Segoe UI", 1, 18)); // NOI18N
        jButton1.setForeground(new java.awt.Color(240, 241, 247));
        jButton1.setText("Cancel");
        jButton1.setOpaque(true);
        jButton1.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton1ActionPerformed(evt);
            }
        });
        getContentPane().add(jButton1);
        jButton1.setBounds(300, 480, 190, 40);

        jButton2.setBackground(new java.awt.Color(77, 34, 89));
        jButton2.setFont(new java.awt.Font("Segoe UI", 1, 18)); // NOI18N
        jButton2.setForeground(new java.awt.Color(240, 241, 247));
        jButton2.setText("Sign up");
        jButton2.setOpaque(true);
        jButton2.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton2ActionPerformed(evt);
            }
        });
        getContentPane().add(jButton2);
        jButton2.setBounds(90, 480, 190, 40);

        jTextField2.setBackground(new java.awt.Color(77, 34, 89));
        jTextField2.setForeground(new java.awt.Color(240, 241, 247));
        jTextField2.setText("Enter your name");
        jTextField2.setOpaque(true);
        jTextField2.addFocusListener(new java.awt.event.FocusAdapter() {
            public void focusLost(java.awt.event.FocusEvent evt) {
                jTextField2FocusLost(evt);
            }
        });
        jTextField2.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jTextField2ActionPerformed(evt);
            }
        });
        getContentPane().add(jTextField2);
        jTextField2.setBounds(300, 130, 190, 40);

        jTextField4.setBackground(new java.awt.Color(77, 34, 89));
        jTextField4.setForeground(new java.awt.Color(240, 241, 247));
        jTextField4.setText("Enter your phone number");
        jTextField4.setOpaque(true);
        jTextField4.addFocusListener(new java.awt.event.FocusAdapter() {
            public void focusLost(java.awt.event.FocusEvent evt) {
                jTextField4FocusLost(evt);
            }
        });
        jTextField4.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jTextField4ActionPerformed(evt);
            }
        });
        getContentPane().add(jTextField4);
        jTextField4.setBounds(300, 190, 190, 40);

        jTextField3.setBackground(new java.awt.Color(77, 34, 89));
        jTextField3.setForeground(new java.awt.Color(240, 241, 247));
        jTextField3.setText("Enter a Username");
        jTextField3.setOpaque(true);
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
        jTextField3.setBounds(300, 250, 190, 40);

        jPasswordField1.setBackground(new java.awt.Color(77, 34, 89));
        jPasswordField1.setForeground(new java.awt.Color(240, 241, 247));
        jPasswordField1.setText("jPasswordField1");
        jPasswordField1.setOpaque(true);
        jPasswordField1.addFocusListener(new java.awt.event.FocusAdapter() {
            public void focusLost(java.awt.event.FocusEvent evt) {
                jPasswordField1FocusLost(evt);
            }
        });
        getContentPane().add(jPasswordField1);
        jPasswordField1.setBounds(300, 370, 190, 40);

        jPasswordField2.setBackground(new java.awt.Color(77, 34, 89));
        jPasswordField2.setForeground(new java.awt.Color(240, 241, 247));
        jPasswordField2.setText("jPasswordField1");
        jPasswordField2.setOpaque(true);
        jPasswordField2.addFocusListener(new java.awt.event.FocusAdapter() {
            public void focusLost(java.awt.event.FocusEvent evt) {
                jPasswordField2FocusLost(evt);
            }
        });
        getContentPane().add(jPasswordField2);
        jPasswordField2.setBounds(300, 310, 190, 40);

        jLabel9.setFont(new java.awt.Font("Segoe UI", 1, 14)); // NOI18N
        jLabel9.setForeground(new java.awt.Color(165, 0, 0));
        jLabel9.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
        jLabel9.setText("*Invalid");
        getContentPane().add(jLabel9);
        jLabel9.setBounds(500, 130, 60, 40);

        jLabel10.setBackground(new java.awt.Color(34, 24, 59));
        jLabel10.setFont(new java.awt.Font("Segoe UI", 1, 14)); // NOI18N
        jLabel10.setForeground(new java.awt.Color(255, 0, 0));
        jLabel10.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
        jLabel10.setOpaque(true);
        getContentPane().add(jLabel10);
        jLabel10.setBounds(165, 430, 250, 30);

        jLabel11.setFont(new java.awt.Font("Segoe UI", 1, 14)); // NOI18N
        jLabel11.setForeground(new java.awt.Color(165, 0, 0));
        jLabel11.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
        jLabel11.setText("*Invalid");
        getContentPane().add(jLabel11);
        jLabel11.setBounds(500, 190, 60, 40);

        jLabel12.setFont(new java.awt.Font("Segoe UI", 1, 14)); // NOI18N
        jLabel12.setForeground(new java.awt.Color(165, 0, 0));
        jLabel12.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
        jLabel12.setText("*Invalid");
        getContentPane().add(jLabel12);
        jLabel12.setBounds(500, 250, 60, 40);

        jLabel7.setIcon(new javax.swing.ImageIcon(getClass().getResource("/resources/auct.jpg"))); // NOI18N
        getContentPane().add(jLabel7);
        jLabel7.setBounds(0, 0, 580, 600);

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private void jButton1ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton1ActionPerformed
        this.dispose();
        LoginScreen login = new LoginScreen();
        login.setVisible(true);
    }//GEN-LAST:event_jButton1ActionPerformed

    private void jButton2ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton2ActionPerformed
        name = jTextField2.getText();
        phn = jTextField4.getText();
        uname = jTextField3.getText();
        pass = String.valueOf(jPasswordField2.getPassword());
        rpass = String.valueOf(jPasswordField1.getPassword());

        if(name.isBlank() || phn.isBlank() || !obj.isNumeric(phn) || uname.isBlank() || pass.isBlank() || !pass.equals(rpass))
        {
            if(pass.isBlank())
            {
                jLabel10.setText("*Password field can not be empty");
                jLabel10.setVisible(true);
            }
            else
                jLabel10.setVisible(false);
            
            if(!pass.equals(rpass))
            {
                jLabel10.setText("*Password not match");
                jLabel10.setVisible(true);
            }
            else
                jLabel10.setVisible(false);
            
            if(phn.isBlank() || !obj.isNumeric(phn))
                jLabel11.setVisible(true);
            else
                jLabel11.setVisible(false);
            
            if(uname.isBlank())
                jLabel12.setVisible(true);
            else
                jLabel12.setVisible(false);
            
            if(name.isBlank())
                jLabel9.setVisible(true);
            else
                jLabel9.setVisible(false);
        }
        else
        {
            jLabel9.setVisible(false);
            jLabel11.setVisible(false);
            jLabel12.setVisible(false);
            jLabel10.setVisible(false);

            try
            {
                if(obj.matchText(uname, "uname"))
                {
                    jLabel10.setText("*Username Already Exists");
                    jLabel10.setVisible(true);
                }
                else
                {
                    obj.store_to_file(name, phn, uname, pass);
                    String[] call = "call to method".split("");
                    SignedUpSuccess.main(call);
                    this.dispose();
                }
            }
            catch(IOException e)
            {
                System.out.println("ERROR : "+ e);
            }
        }

    }//GEN-LAST:event_jButton2ActionPerformed

    private void jTextField4ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jTextField4ActionPerformed
    }//GEN-LAST:event_jTextField4ActionPerformed

    private void jTextField3ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jTextField3ActionPerformed
    }//GEN-LAST:event_jTextField3ActionPerformed

    private void jTextField4FocusLost(java.awt.event.FocusEvent evt) {//GEN-FIRST:event_jTextField4FocusLost
        phn = jTextField4.getText();
        if(phn.isBlank() || !obj.isNumeric(phn))
            jLabel11.setVisible(true);
        else
            jLabel11.setVisible(false);
    }//GEN-LAST:event_jTextField4FocusLost

    private void jTextField3FocusLost(java.awt.event.FocusEvent evt) {//GEN-FIRST:event_jTextField3FocusLost
        uname = jTextField3.getText();
        if(uname.isBlank())
            jLabel12.setVisible(true);
        else
            jLabel12.setVisible(false);
    }//GEN-LAST:event_jTextField3FocusLost

    private void jPasswordField2FocusLost(java.awt.event.FocusEvent evt) {//GEN-FIRST:event_jPasswordField2FocusLost
        pass = String.valueOf(jPasswordField2.getPassword());
        if(pass.isBlank())
        {
            jLabel10.setText("*Password field can not be empty");
            jLabel10.setVisible(true);
        }
        else
            jLabel10.setVisible(false);
    }//GEN-LAST:event_jPasswordField2FocusLost

    private void jPasswordField1FocusLost(java.awt.event.FocusEvent evt) {//GEN-FIRST:event_jPasswordField1FocusLost
        pass = String.valueOf(jPasswordField2.getPassword());
        rpass = String.valueOf(jPasswordField1.getPassword());
        if(!pass.equals(rpass))
        {
            jLabel10.setText("*Password not match");
            jLabel10.setVisible(true);
        }
        else
            jLabel10.setVisible(false);
    }//GEN-LAST:event_jPasswordField1FocusLost

    private void jTextField2FocusLost(java.awt.event.FocusEvent evt) {//GEN-FIRST:event_jTextField2FocusLost
        name = jTextField2.getText();
        if(name.isBlank())
            jLabel9.setVisible(true);
        else
            jLabel9.setVisible(false);
    }//GEN-LAST:event_jTextField2FocusLost

    private void jTextField2ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jTextField2ActionPerformed
    }//GEN-LAST:event_jTextField2ActionPerformed

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
            java.util.logging.Logger.getLogger(SignupScreen.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (InstantiationException ex) {
            java.util.logging.Logger.getLogger(SignupScreen.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (IllegalAccessException ex) {
            java.util.logging.Logger.getLogger(SignupScreen.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (javax.swing.UnsupportedLookAndFeelException ex) {
            java.util.logging.Logger.getLogger(SignupScreen.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        }
        //</editor-fold>

        /* Create and display the form */
        java.awt.EventQueue.invokeLater(new Runnable() {
            public void run() {
                new SignupScreen().setVisible(true);
            }
        });
    }

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton jButton1;
    private javax.swing.JButton jButton2;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel10;
    private javax.swing.JLabel jLabel11;
    private javax.swing.JLabel jLabel12;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JLabel jLabel4;
    private javax.swing.JLabel jLabel5;
    private javax.swing.JLabel jLabel6;
    private javax.swing.JLabel jLabel7;
    private javax.swing.JLabel jLabel9;
    private javax.swing.JPasswordField jPasswordField1;
    private javax.swing.JPasswordField jPasswordField2;
    private javax.swing.JTextField jTextField2;
    private javax.swing.JTextField jTextField3;
    private javax.swing.JTextField jTextField4;
    // End of variables declaration//GEN-END:variables
}