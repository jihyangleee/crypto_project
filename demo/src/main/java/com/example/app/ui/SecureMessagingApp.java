package com.example.app.ui;

import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.stage.Stage;

public class SecureMessagingApp extends Application {

    @Override
    public void start(Stage primaryStage) throws Exception {
        FXMLLoader loader = new FXMLLoader(getClass().getResource("/app/view/MainView.fxml"));
        Parent root = loader.load();
        
        Scene scene = new Scene(root, 1400, 900);
        
        primaryStage.setTitle("Secure Messaging & Signature Verification System");
        primaryStage.setScene(scene);
        primaryStage.show();
    }

    public static void main(String[] args) {
        launch(args);
    }
}
