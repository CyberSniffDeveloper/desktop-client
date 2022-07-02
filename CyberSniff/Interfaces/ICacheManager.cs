namespace CyberSniff.Interfaces;

public interface ICacheManager<T>
{
    void ClearCache();
    T GetCache();
    void WriteCache(T cache);
}