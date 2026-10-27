import java.awt.Color;

/**
 * Pixel represents an individual pixel inside an image,
 * storing its Cartesian coordinates (x, y) and its RGB color value.
 */
public class Pixel {
    private int x;
    private int y;
    private Color color;

    /**
     * Constructs a Pixel with coordinates and color.
     *
     * @param x Horizontal coordinate.
     * @param y Vertical coordinate.
     * @param color The {@link Color} of the pixel.
     */
    public Pixel(int x, int y, Color color) {
        this.x = x;
        this.y = y;
        this.color = color;
    }

    public int getX() {
        return x;
    }

    public int getY() {
        return y;
    }

    public Color getColor() {
        return color;
    }

    public void setX(int x) {
        this.x = x;
    }

    public void setY(int y) {
        this.y = y;
    }

    public void setColor(Color color) {
        this.color = color;
    }
}
