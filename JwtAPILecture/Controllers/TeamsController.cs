using JwtAPILecture.Data;
using JwtAPILecture.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace JwtAPILecture.Controllers;

[Route("api/[controller]")]
[ApiController]
public class TeamsController : ControllerBase
{
    private static AppDbContext _context;
    public TeamsController(AppDbContext context)
    {
        _context = context;
    }

    //private static List<Team> teams = new List<Team>()
    //{
    //    new Team()
    //    {
    //        Id = 1,
    //        Country = "Brasil",
    //        Name = "Test",
    //        TeamPrinciple = "Vini Boladao"
    //    },
    //    new Team()
    //    {
    //        Id = 2,
    //        Country = "Italy",
    //        Name = "Test2",
    //        TeamPrinciple = "Vini nao tao bolado"
    //    },
    //    new Team()
    //    {
    //        Id = 3,
    //        Country = "Germany",
    //        Name = "Test3",
    //        TeamPrinciple = "Vini boladinho"
    //    }
    //};

    [HttpGet]
    public async Task<IActionResult> Get()
    {
        var teams = await _context.Teams.ToListAsync();

        return Ok(teams);
    }

    [HttpGet("{id:int}")]
    public async Task<IActionResult> Get(int id)
    {
        var team = await _context.Teams.FirstOrDefaultAsync(t => t.Id == id);

        if (team == null)
            return BadRequest("Invalid Id");

        return Ok(team);
    }

    [HttpPost]
    public async Task<IActionResult> Post(Team team)
    {
        await _context.Teams.AddAsync(team);
        await _context.SaveChangesAsync();

        return CreatedAtAction("Get", team.Id, team);
    }

    [HttpPatch]
    public async Task<IActionResult> Patch(int id, string country)
    {
        var team = await _context.Teams.FirstOrDefaultAsync(x => x.Id == id);

        if (team == null) return BadRequest("Invalid Id");
        
        team.Country = country;
        _context.Teams.Update(team);
        await _context.SaveChangesAsync();

        return NoContent();
    }

    [HttpDelete]
    public async Task<IActionResult> Delete(int id)
    {
        var team = await _context.Teams.FirstOrDefaultAsync(x => x.Id == id);
        if (team == null) return BadRequest("Invalid Id");

        _context.Teams.Remove(team);
        await _context.SaveChangesAsync();

        return NoContent();
    }
}

