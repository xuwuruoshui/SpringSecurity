package top.xuwuruoshui.springsecurity.utils;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class ResultVo {
    private String info;
    private String url;
    private int status;


    public static ResultVo getResultVo(String info,String url,int status){
        return new ResultVo(info,url,status);
    }

    public static ResultVo success(){
        return new ResultVo("登录成功","/index",200);
    }

    public static ResultVo failed(){
        return new ResultVo("登录失败","/login",401);
    }
}
