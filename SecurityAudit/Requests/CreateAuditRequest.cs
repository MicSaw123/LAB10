using System.ComponentModel.DataAnnotations;

namespace SecurityAudit.Requests
{
    public class CreateAuditRequest
    {
        [Required(ErrorMessage = "Tytul jest wymagany")]
        [StringLength(200, MinimumLength = 1)]
        [RegularExpression(@"^[ \w\s\-\.\,]+$", ErrorMessage = "Niedozwolone znaki w tytule")]
        public string Title { get; set; } = "";

        [StringLength(2000)]
        public string? Description { get; set; }

        [Range(1, 5, ErrorMessage = "Priorytet musi byc od 1 do 5")]
        public int Priority { get; set; } = 3;
    }
}
