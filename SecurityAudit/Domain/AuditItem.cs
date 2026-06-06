namespace SecurityAudit.Domain
{
    public class AuditItem
    {
        public int Id { get; set; }
        public string Title { get; set; } = string.Empty;
        public string? Description { get; set; }
        public int Priority { get; set; }
    }
}
