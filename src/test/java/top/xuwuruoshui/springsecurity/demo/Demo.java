package top.xuwuruoshui.springsecurity.demo;

public class Demo {
    public static void main(String[] args) {
        Demo demo = new Demo(1,"qwe",1);
        System.out.println(demo);
        demo.setAge(2);
        System.out.println(demo);
    }

    @Override
    public String toString() {
        return "Demo{" +
                "id=" + id +
                ", name='" + name + '\'' +
                ", age=" + age +
                '}';
    }

    private int id;
    private String name;
    private int age;

    public Demo() {
    }

    public Demo(int id, String name, int age) {
        this.id = id;
        this.name = name;
        this.age = age;
    }

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id+this.age;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public int getAge() {
        return age;
    }

    public void setAge(int age) {
        this.age = age;
    }
}
