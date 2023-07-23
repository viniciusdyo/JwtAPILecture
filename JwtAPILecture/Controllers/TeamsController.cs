using JwtAPILecture.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace JwtAPILecture.Controllers;

[Route("api/[controller]")]
[ApiController]
public class TeamsController : ControllerBase
{
    private static List<Team> teams = new List<Team>()
    {
        new Team()
        {
            Id = 1,
            Country = "Brasil",
            Name = "Test",
            TeamPrinciple = "Vini Boladao"
        },
        new Team()
        {
            Id = 2,
            Country = "Italy",
            Name = "Test2",
            TeamPrinciple = "Vini nao tao bolado"
        },
        new Team()
        {
            Id = 3,
            Country = "Germany",
            Name = "Test3",
            TeamPrinciple = "Vini boladinho"
        }
    };

    [HttpGet]
    public IActionResult Get()
    {
        return Ok(teams);
    }

    [HttpGet("{id:int}")]
    public IActionResult Get(int id)
    {
        var team = teams.FirstOrDefault(t => t.Id == id);

        if (team == null)
            return BadRequest("Invalid Id");
        
        return Ok(team);
    }

    [HttpPost]
    public IActionResult Post(Team team)
    {
        teams.Add(team);

        return CreatedAtAction("Get", team.Id, team);
    }

    [HttpPatch]
    public IActionResult Patch(int id, string country)
    {
        var team = teams.FirstOrDefault(x => x.Id == id);

        if (team == null) return BadRequest("Invalid Id");

        team.Country= country;

        return NoContent();
    }

    [HttpDelete]
    public IActionResult Delete(int id)
    {
        var team = teams.FirstOrDefault(x => x.Id == id);
        if (team == null) return BadRequest("Invalid Id");

        teams.Remove(team);

        return NoContent();
    }
}

