package big;

import java.math.BigInteger;
import java.text.SimpleDateFormat;
import java.util.Date;

/**
 * Created by ligson on 2016/4/18.
 */
public class BigTest {
    public static void main(String[] args) {
        Date date = new Date();
        SimpleDateFormat sdf = new SimpleDateFormat("yyyyMMddHHmmss");
        String id = sdf.format(date);
        int num = (int)(Math.random()*100000);
        String numStr = num+"";
        int padding = 6-numStr.length();
        for(int i =0;i<padding;i++){
            numStr="0"+numStr;
        }
        id=id+numStr;
        BigInteger bigInteger = new BigInteger(id);
        System.out.println(bigInteger);
    }
}
