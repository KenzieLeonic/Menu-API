package th.ac.ku.menu.model;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import java.util.UUID;

@Entity
//สร้าง ตารางชื่อเมนูอัตโนมัติ
public class Menu {
    //User id format
    @Id //add primary key
    @GeneratedValue //ให้ auto gen id ให้ ถ้าเป็น UID จะ random safe กว่า
    private UUID id;

    //สร้าง column ให้ อัตโนมัติ
    private String name;
    private double price;
    private String category;


    //getter and setter
    public UUID getId() {
        return id;
    }

    public String getName() {
        return name;
    }

    public double getPrice() {
        return price;
    }

    public String getCategory() {
        return category;
    }

    public void setId(UUID id) {
        this.id = id;
    }

    public void setName(String name) {
        this.name = name;
    }

    public void setPrice(double price) {
        this.price = price;
    }

    public void setCategory(String category) {
        this.category = category;
    }
}
